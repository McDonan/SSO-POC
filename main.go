package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html"
	"io"
	"net/http"
	"net/url"
	"os"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/MicahParks/keyfunc/v3"
	"github.com/golang-jwt/jwt/v5"
)

func main() {
	domain := strings.TrimRight(mustEnv("COGNITO_DOMAIN"), "/")
	region, poolID := mustEnv("COGNITO_REGION"), mustEnv("COGNITO_USER_POOL_ID")
	clientID := mustEnv("COGNITO_APP_CLIENT_ID")
	idps := splitList(os.Getenv("COGNITO_IDP_NAMES"))
	if len(idps) == 0 {
		idps = splitList(mustEnv("COGNITO_IDP_NAME"))
	}
	secret := os.Getenv("COGNITO_APP_CLIENT_SECRET")
	redirectURI := "http://localhost:8085/callback"

	iss := fmt.Sprintf("https://cognito-idp.%s.amazonaws.com/%s", region, poolID)
	kf, err := keyfunc.NewDefaultCtx(context.Background(), []string{iss + "/.well-known/jwks.json"})
	if err != nil {
		fail("jwks: %v", err)
	}

	type login struct{ verifier, idp string }
	var mu sync.Mutex
	pending := map[string]login{}

	done := make(chan struct{})
	var once sync.Once
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if len(idps) == 1 {
			http.Redirect(w, r, "/login?idp="+url.QueryEscape(idps[0]), 302)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprint(w, "<h3>Sign in with</h3><ul>")
		for _, p := range idps {
			fmt.Fprintf(w, `<li><a href="/login?idp=%s">%s</a></li>`, url.QueryEscape(p), html.EscapeString(p))
		}
		fmt.Fprint(w, "</ul>")
	})
	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		idp := r.URL.Query().Get("idp")
		if !slices.Contains(idps, idp) {
			http.Error(w, "unknown identity provider", 400)
			return
		}
		state, verifier := rnd(24), rnd(48)
		mu.Lock()
		pending[state] = login{verifier, idp}
		mu.Unlock()
		sum := sha256.Sum256([]byte(verifier))
		http.Redirect(w, r, domain+"/oauth2/authorize?"+url.Values{
			"response_type": {"code"}, "client_id": {clientID}, "redirect_uri": {redirectURI},
			"scope": {"openid email profile"}, "identity_provider": {idp}, "state": {state},
			"code_challenge": {base64.RawURLEncoding.EncodeToString(sum[:])}, "code_challenge_method": {"S256"},
		}.Encode(), 302)
	})
	mux.HandleFunc("/callback", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		mu.Lock()
		l, ok := pending[q.Get("state")]
		delete(pending, q.Get("state"))
		mu.Unlock()
		if !ok || q.Get("code") == "" {
			msg := "FAIL callback: " + q.Get("error") + " " + q.Get("error_description")
			http.Error(w, msg, 400)
			fmt.Println(msg)
			return
		}
		defer once.Do(func() { close(done) })
		out, err := exchange(r.Context(), kf, iss, domain, clientID, secret, redirectURI, q.Get("code"), l.verifier)
		if err != nil {
			http.Error(w, err.Error(), 502)
			fmt.Printf("FAIL [%s] %v\n", l.idp, err)
			return
		}
		out = "idp: " + l.idp + "\n" + out
		fmt.Fprint(w, "<pre>"+html.EscapeString(out)+"</pre>")
		fmt.Println(out)
	})

	srv := &http.Server{Addr: "127.0.0.1:8085", Handler: mux}
	go srv.ListenAndServe()
	fmt.Println("open http://localhost:8085 in a browser (providers: " + strings.Join(idps, ", ") + ")")
	<-done
	time.Sleep(500 * time.Millisecond)
	srv.Shutdown(context.Background())
}

func exchange(ctx context.Context, kf keyfunc.Keyfunc, iss, domain, clientID, secret, redirectURI, code, verifier string) (string, error) {
	form := url.Values{"grant_type": {"authorization_code"}, "client_id": {clientID},
		"code": {code}, "redirect_uri": {redirectURI}, "code_verifier": {verifier}}
	req, _ := http.NewRequestWithContext(ctx, "POST", domain+"/oauth2/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if secret != "" {
		req.SetBasicAuth(clientID, secret)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		return "", fmt.Errorf("token exchange %d: %s", resp.StatusCode, body)
	}
	var tok struct {
		IDToken      string `json:"id_token"`
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
	}
	if err := json.Unmarshal(body, &tok); err != nil {
		return "", err
	}

	idc, err := parse(kf, tok.IDToken, jwt.WithIssuer(iss), jwt.WithAudience(clientID))
	if err != nil {
		return "", fmt.Errorf("id token rejected: %w", err)
	}
	if idc["token_use"] != "id" {
		return "", fmt.Errorf("id token token_use=%v", idc["token_use"])
	}
	acc, err := parse(kf, tok.AccessToken, jwt.WithIssuer(iss))
	if err != nil {
		return "", fmt.Errorf("access token rejected: %w", err)
	}
	if acc["token_use"] != "access" || acc["client_id"] != clientID {
		return "", fmt.Errorf("access token token_use=%v client_id=%v", acc["token_use"], acc["client_id"])
	}

	ident, _ := json.MarshalIndent(idc["identities"], "", "  ")
	return fmt.Sprintf("PASS Cognito issued verified tokens for an external-IdP login\niss: %v\ncognito:username: %v\nsub: %v\nemail: %v\naccess sub == id sub: %t\nrefresh token present: %t\nidentities: %s",
		idc["iss"], idc["cognito:username"], idc["sub"], idc["email"],
		acc["sub"] == idc["sub"], tok.RefreshToken != "", ident), nil
}

func parse(kf keyfunc.Keyfunc, raw string, opts ...jwt.ParserOption) (jwt.MapClaims, error) {
	opts = append(opts, jwt.WithValidMethods([]string{"RS256"}), jwt.WithExpirationRequired())
	t, err := jwt.Parse(raw, kf.Keyfunc, opts...)
	if err != nil {
		return nil, err
	}
	return t.Claims.(jwt.MapClaims), nil
}

func splitList(s string) (out []string) {
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func rnd(n int) string {
	b := make([]byte, n)
	rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)[:n]
}

func mustEnv(k string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	fail("missing env %s", k)
	return ""
}

func fail(f string, a ...any) {
	fmt.Fprintf(os.Stderr, f+"\n", a...)
	os.Exit(1)
}
