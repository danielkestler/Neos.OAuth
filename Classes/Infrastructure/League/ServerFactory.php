<?php
declare(strict_types=1);

namespace Neos\OAuth\Infrastructure\League;

use League\OAuth2\Server\AuthorizationServer;
use League\OAuth2\Server\Grant\AuthCodeGrant;
use League\OAuth2\Server\Grant\ClientCredentialsGrant;
use League\OAuth2\Server\Grant\RefreshTokenGrant;
use League\OAuth2\Server\ResourceServer;
use Neos\Flow\Annotations as Flow;
use Neos\OAuth\Infrastructure\League\Repository\AccessTokenRepository;
use Neos\OAuth\Infrastructure\League\Repository\AuthCodeRepository;
use Neos\OAuth\Infrastructure\League\Repository\ClientRepository;
use Neos\OAuth\Infrastructure\League\Repository\RefreshTokenRepository;
use Neos\OAuth\Infrastructure\League\Repository\ScopeRepository;

#[Flow\Scope('singleton')]
final class ServerFactory
{
    /**
     * @var array{accessToken: string, refreshToken: string, authCode: string}
     */
    #[Flow\InjectConfiguration(path: 'ttl', package: 'Neos.OAuth')]
    protected array $ttl;

    private ?AuthorizationServer $authorizationServer = null;

    private ?ResourceServer $resourceServer = null;

    public function __construct(
        private readonly KeyManager $keyManager,
        private readonly ClientRepository $clientRepository,
        private readonly AccessTokenRepository $accessTokenRepository,
        private readonly RefreshTokenRepository $refreshTokenRepository,
        private readonly AuthCodeRepository $authCodeRepository,
        private readonly ScopeRepository $scopeRepository,
    ) {
    }

    public function getAuthorizationServer(): AuthorizationServer
    {
        if ($this->authorizationServer !== null) {
            return $this->authorizationServer;
        }
        $server = new AuthorizationServer(
            $this->clientRepository,
            $this->accessTokenRepository,
            $this->scopeRepository,
            $this->keyManager->getPrivateKey(),
            $this->keyManager->getEncryptionKey(),
        );
        $accessTokenTtl = new \DateInterval($this->ttl['accessToken']);
        $refreshTokenTtl = new \DateInterval($this->ttl['refreshToken']);

        // PKCE is required and restricted to S256 by the AuthorizeController, league 8 cannot be configured to do so
        $authCodeGrant = new AuthCodeGrant($this->authCodeRepository, $this->refreshTokenRepository, new \DateInterval($this->ttl['authCode']));
        $authCodeGrant->setRefreshTokenTTL($refreshTokenTtl);
        $server->enableGrantType($authCodeGrant, $accessTokenTtl);

        // Refresh tokens are rotated: each use revokes the old one
        $refreshTokenGrant = new RefreshTokenGrant($this->refreshTokenRepository);
        $refreshTokenGrant->setRefreshTokenTTL($refreshTokenTtl);
        $server->enableGrantType($refreshTokenGrant, $accessTokenTtl);

        $server->enableGrantType(new ClientCredentialsGrant(), $accessTokenTtl);

        return $this->authorizationServer = $server;
    }

    public function getResourceServer(): ResourceServer
    {
        return $this->resourceServer ??= new ResourceServer($this->accessTokenRepository, $this->keyManager->getPublicKey());
    }
}
