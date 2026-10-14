<?php
declare(strict_types=1);

namespace Neos\OAuth\Infrastructure\League;

use League\OAuth2\Server\Entities\ClientEntityInterface;
use League\OAuth2\Server\Grant;
use Neos\Flow\Annotations as Flow;
use Psr\Http\Message\ServerRequestInterface;

/**
 * league's authorization code grant, accepting any port for "localhost" redirect URIs, too
 *
 * Native apps receive the code on a loopback port they pick at random, so the port of a loopback redirect URI must not
 * matter (RFC 8252 section 7.3). league ignores it for 127.0.0.1 and [::1] only, but many native apps, among them MCP
 * clients like Claude Code, register http://localhost/... instead (allowed, if discouraged, by RFC 8252 section 8.3)
 */
#[Flow\Proxy(false)]
final class AuthCodeGrant extends Grant\AuthCodeGrant
{
    protected function validateRedirectUri(string $redirectUri, ClientEntityInterface $client, ServerRequestInterface $request)
    {
        $withoutPort = self::localhostWithoutPort($redirectUri);
        if ($withoutPort !== null) {
            foreach ((array)$client->getRedirectUri() as $allowedRedirectUri) {
                if (self::localhostWithoutPort((string)$allowedRedirectUri) === $withoutPort) {
                    return;
                }
            }
        }
        parent::validateRedirectUri($redirectUri, $client, $request);
    }

    /**
     * The URI without its port if it is an http://localhost URI, else null
     */
    private static function localhostWithoutPort(string $uri): ?string
    {
        $parts = parse_url($uri);
        if ($parts === false || ($parts['scheme'] ?? null) !== 'http' || strtolower($parts['host'] ?? '') !== 'localhost' || isset($parts['user']) || isset($parts['pass']) || isset($parts['fragment'])) {
            return null;
        }
        return 'http://localhost' . ($parts['path'] ?? '') . (isset($parts['query']) ? '?' . $parts['query'] : '');
    }
}
