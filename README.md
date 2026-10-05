# ssopoc

Proof of concept: sign in through **Amazon Cognito** using one or more **external identity providers** (Auth0, Google, Okta, any OIDC/SAML IdP configured in the user pool), and verify the tokens Cognito issues.

## How it works

1. Starts a local server on `http://localhost:8085`.
2. `/` lists the configured providers (auto-redirects if there is only one).
3. `/login?idp=<name>` starts an OAuth2 authorization code flow with PKCE (S256) and a per-login `state`, passing Cognito's `identity_provider` parameter.
4. `/callback` exchanges the code at Cognito's `/oauth2/token` endpoint.
5. The ID and access tokens are verified against the user pool JWKS (RS256, issuer, audience/client_id, `token_use`, expiry) and the result is printed and shown in the browser.

The process exits after the first callback.

## Prerequisites

- Go 1.21+
- A Cognito user pool with a hosted-UI domain and an app client
- Callback URL `http://localhost:8085/callback` allowed on the app client
- Each external IdP added to the pool and enabled on the app client

## Configuration

Copy `.env.example` to `.env` and fill it in.

| Variable | Required | Description |
|---|---|---|
| `COGNITO_DOMAIN` | yes | Hosted UI domain URL |
| `COGNITO_REGION` | yes | User pool region |
| `COGNITO_USER_POOL_ID` | yes | User pool ID |
| `COGNITO_APP_CLIENT_ID` | yes | App client ID |
| `COGNITO_APP_CLIENT_SECRET` | no | App client secret (confidential clients) |
| `COGNITO_IDP_NAMES` | yes* | Comma-separated provider names, e.g. `Auth0-Poc,Google,Okta` |
| `COGNITO_IDP_NAME` | yes* | Legacy single-provider name, used if `COGNITO_IDP_NAMES` is unset |

## Run

```sh
make run
```

Open http://localhost:8085 and choose a provider.

## Adding a provider

Add the IdP in Cognito, enable it on the app client, and append its exact name to `COGNITO_IDP_NAMES`. No code changes are needed.

## Security note

`.env` is git-ignored. The previous Makefile contained a client secret in plain text; rotate that secret.
