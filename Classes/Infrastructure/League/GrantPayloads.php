<?php
declare(strict_types=1);

namespace Neos\OAuth\Infrastructure\League;

use League\OAuth2\Server\CryptTrait;
use Neos\Flow\Annotations as Flow;

/**
 * Reads which code or refresh token a token request presents, by decrypting it as league does
 *
 * The token endpoint needs it before league issues the tokens: they inherit the audience of the code or refresh token
 * (RFC 8707). Anything that doesn't decrypt yields null, league then rejects the request itself
 */
#[Flow\Scope('singleton')]
final class GrantPayloads
{
    use CryptTrait;

    public function __construct(KeyManager $keyManager)
    {
        $this->setEncryptionKey($keyManager->getEncryptionKey());
    }

    /**
     * The identifier of the authorization code's TokenRecord
     */
    public function authCodeIdentifier(string $code): ?string
    {
        return $this->field($code, 'auth_code_id');
    }

    /**
     * The identifier of the refresh token's TokenRecord
     */
    public function refreshTokenIdentifier(string $refreshToken): ?string
    {
        return $this->field($refreshToken, 'refresh_token_id');
    }

    private function field(string $encrypted, string $name): ?string
    {
        try {
            $payload = json_decode($this->decrypt($encrypted), true, flags: JSON_THROW_ON_ERROR);
        } catch (\Throwable) {
            return null;
        }
        $value = is_array($payload) ? ($payload[$name] ?? null) : null;
        return is_string($value) && $value !== '' ? $value : null;
    }
}
