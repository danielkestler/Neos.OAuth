# Neos.OAuth

An OAuth 2 authorization server for Neos 9, based on [league/oauth2-server](https://oauth2.thephpleague.com). Users
log in with their Neos account and approve a client; the client gets a bearer token that acts as that account.

## Setup

Run `./flow doctrine:migrate`, then `./flow oauth:status`, which checks the keys, tables, issuer, scopes and clients and
tells how to fix what's missing. The issuer is `Neos.OAuth.issuer`, or else `Neos.Flow.http.baseUri` or the primary
domain of the default site. The keys are generated on first use in `Data/Persistent/Neos.OAuth`, which all servers have
to share, or set in `Neos.OAuth.keys`, e.g. from environment variables.

## Endpoints

- `/oauth/authorize`: login and consent page (authorization code grant with PKCE)
- `/oauth/token`: authorization code, refresh token and client credentials grants
- `/oauth/register`: dynamic client registration ([RFC 7591](https://www.rfc-editor.org/rfc/rfc7591)) for public
  clients, e.g. MCP clients. Disabled by default, enabled in the Development context
- `/.well-known/oauth-authorization-server`: server metadata ([RFC 8414](https://www.rfc-editor.org/rfc/rfc8414))
- `/.well-known/oauth-protected-resource/<path>`: resource metadata ([RFC 9728](https://www.rfc-editor.org/rfc/rfc9728))

## Clients

Packages declare public clients in `Neos.OAuth.clients`, see `Configuration/Settings.yaml`. Other clients are managed
on the command line: `oauth:createclient` (public or `--confidential`, optionally `client_credentials` with an
`--account`), `oauth:listclients`, `oauth:removeclient` and `oauth:revoketokens`. Run `oauth:prunetokens` regularly to
remove expired tokens.

## Accepting the tokens

A package that accepts the tokens

- registers its scopes in `Neos.OAuth.scopes`, or a `Neos\OAuth\Domain\ScopeProvider` in `Neos.OAuth.scopeProviders`,
- adds a `Uri` request pattern for its URLs to the `Neos.OAuth:Bearer` authentication provider,
- and describes itself in `Neos.OAuth.protectedResources`.

```yaml
Neos:
  OAuth:
    scopes:
      'my.read': 'Read my things'
    protectedResources:
      'Vendor.Package':
        path: 'my-api'
        name: 'My API'
        scopes: ['my.read']
  Flow:
    security:
      authentication:
        providers:
          'Neos.OAuth:Bearer':
            requestPatterns:
              'Vendor.Package:Api':
                pattern: 'Uri'
                patternOptions:
                  uriPattern: '/my-api/.*'
```

`Neos\OAuth\Security\OAuthContext::authenticatedGrant()` returns the current request's token: its account, client and
scopes. Neos.Api is an example.

## License

MIT, see [LICENSE](LICENSE).
