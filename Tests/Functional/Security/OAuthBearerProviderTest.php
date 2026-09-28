<?php
declare(strict_types=1);

namespace Neos\OAuth\Tests\Functional\Security;

use GuzzleHttp\Psr7\ServerRequest;
use Neos\Flow\Security\AccountFactory;
use Neos\Flow\Security\AccountRepository;
use Neos\Flow\Security\Authentication\AuthenticationManagerInterface;
use Neos\Flow\Security\Authentication\Token\BearerToken;
use Neos\Flow\Security\Authentication\TokenAndProviderFactoryInterface;
use Neos\Flow\Tests\FunctionalTestCase;
use Neos\OAuth\Domain\Model\OAuthClient;
use Neos\OAuth\Domain\Model\TokenType;
use Neos\OAuth\Domain\Repository\OAuthClientRepository;
use Neos\OAuth\Domain\Repository\TokenRecordRepository;
use Neos\OAuth\Infrastructure\League\Entity\UserEntity;
use Neos\OAuth\Infrastructure\League\Repository\AccessTokenRepository;
use Neos\OAuth\Infrastructure\League\Repository\ClientRepository;
use Neos\OAuth\Infrastructure\League\Repository\ScopeRepository;
use Neos\OAuth\Infrastructure\League\KeyManager;
use PHPUnit\Framework\Attributes\Test;
use Psr\Http\Message\ResponseInterface;

class OAuthBearerProviderTest extends FunctionalTestCase
{
    protected static $testablePersistenceEnabled = true;

    private const string SECRET = 'machine-secret';

    protected function setUp(): void
    {
        parent::setUp();
        $this->registerRoute('whoami', 'test/neos-oauth/whoami', [
            '@package' => 'Neos.OAuth',
            '@subpackage' => 'Tests\Functional\Fixtures',
            '@controller' => 'Whoami',
            '@action' => 'index',
            '@format' => 'json',
        ]);

        $accountFactory = $this->objectManager->get(AccountFactory::class);
        $accountRepository = $this->objectManager->get(AccountRepository::class);
        $accountRepository->add($accountFactory->createAccountWithPassword('editor', 'password', ['Neos.Neos:Editor'], 'Neos.Neos:Backend'));
        $inactiveAccount = $accountFactory->createAccountWithPassword('expired', 'password', ['Neos.Neos:Editor'], 'Neos.Neos:Backend');
        $inactiveAccount->setExpirationDate(new \DateTime('-1 day'));
        $accountRepository->add($inactiveAccount);

        $clientRepository = $this->objectManager->get(OAuthClientRepository::class);
        $clientRepository->add(new OAuthClient('machine', 'Machine', password_hash(self::SECRET, PASSWORD_DEFAULT), [], [OAuthClient::GRANT_CLIENT_CREDENTIALS], ['neos.oauth.test'], false, 'editor'));
        $clientRepository->add(new OAuthClient('expired-machine', 'Machine of an expired account', password_hash(self::SECRET, PASSWORD_DEFAULT), [], [OAuthClient::GRANT_CLIENT_CREDENTIALS], ['neos.oauth.test'], false, 'expired'));
        $clientRepository->add(new OAuthClient('spa', 'SPA', null, ['http://localhost/callback'], [OAuthClient::GRANT_AUTHORIZATION_CODE], ['neos.oauth.test'], false, null));
        $this->persistenceManager->persistAll();
    }

    #[Test]
    public function clientCredentialsTokensAuthenticateAsTheClientsAccount(): void
    {
        $result = $this->whoami($this->clientCredentialsToken('machine'));

        self::assertTrue($result['authenticated'], json_encode($result));
        self::assertSame('editor', $result['account']);
        self::assertSame('machine', $result['client']);
        self::assertSame(['neos.oauth.test'], $result['scopes']);
        self::assertContains('Neos.Neos:Editor', $result['roles']);
    }

    #[Test]
    public function tokensOfAUserAuthenticateAsThatUsersAccount(): void
    {
        $result = $this->whoami($this->userToken('spa', 'editor'));

        self::assertTrue($result['authenticated']);
        self::assertSame('editor', $result['account']);
        self::assertSame('spa', $result['client']);
    }

    #[Test]
    public function requestsWithoutValidTokenAreNotAuthenticated(): void
    {
        self::assertFalse($this->whoami(null)['authenticated']);
        self::assertFalse($this->whoami('not-a-token')['authenticated']);
        // signed with a different key
        self::assertFalse($this->whoami('eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJlZGl0b3IifQ.c2lnbmF0dXJl')['authenticated']);
    }

    #[Test]
    public function revokedTokensAreRejected(): void
    {
        $token = $this->clientCredentialsToken('machine');
        self::assertTrue($this->whoami($token)['authenticated']);

        $tokenRecordRepository = $this->objectManager->get(TokenRecordRepository::class);
        foreach ($tokenRecordRepository->findActive('machine', null, new \DateTimeImmutable()) as $record) {
            self::assertSame(TokenType::ACCESS_TOKEN, $record->getType());
            $record->revoke();
            $tokenRecordRepository->update($record);
        }
        $this->persistenceManager->persistAll();

        self::assertFalse($this->whoami($token)['authenticated']);
    }

    #[Test]
    public function tokensOfRemovedClientsAreRejected(): void
    {
        $token = $this->clientCredentialsToken('machine');

        $clientRepository = $this->objectManager->get(OAuthClientRepository::class);
        $clientRepository->remove($clientRepository->findOneByClientIdentifier('machine'));
        $this->persistenceManager->persistAll();

        self::assertFalse($this->whoami($token)['authenticated']);
    }

    #[Test]
    public function tokensOfInactiveAccountsAreRejected(): void
    {
        self::assertFalse($this->whoami($this->clientCredentialsToken('expired-machine'))['authenticated']);
        self::assertFalse($this->whoami($this->userToken('spa', 'expired'))['authenticated']);
        self::assertFalse($this->whoami($this->userToken('spa', 'unknown'))['authenticated']);
    }

    #[Test]
    public function publicClientsCannotUseTheClientCredentialsGrant(): void
    {
        $response = $this->browser->request('http://localhost/oauth/token', 'POST', ['grant_type' => 'client_credentials', 'client_id' => 'spa']);
        self::assertSame(401, $response->getStatusCode());
        self::assertSame('invalid_client', json_decode((string)$response->getBody(), true)['error']);
    }

    private function clientCredentialsToken(string $clientIdentifier): string
    {
        $response = $this->browser->request('http://localhost/oauth/token', 'POST', [
            'grant_type' => 'client_credentials',
            'client_id' => $clientIdentifier,
            'client_secret' => self::SECRET,
            'scope' => 'neos.oauth.test',
        ]);
        self::assertSame(200, $response->getStatusCode(), (string)$response->getBody());
        return json_decode((string)$response->getBody(), true, flags: JSON_THROW_ON_ERROR)['access_token'];
    }

    /**
     * Issues a token as the authorization code grant would, without the browser round trip
     */
    private function userToken(string $clientIdentifier, string $accountIdentifier): string
    {
        $client = $this->objectManager->get(ClientRepository::class)->getClientEntity($clientIdentifier);
        $accessTokenRepository = $this->objectManager->get(AccessTokenRepository::class);
        $scope = $this->objectManager->get(ScopeRepository::class)->getScopeEntityByIdentifier('neos.oauth.test');
        $accessToken = $accessTokenRepository->getNewToken($client, [$scope], (new UserEntity($accountIdentifier))->getIdentifier());
        $accessToken->setIdentifier(bin2hex(random_bytes(20)));
        $accessToken->setExpiryDateTime(new \DateTimeImmutable('+1 hour'));
        $accessToken->setPrivateKey($this->objectManager->get(KeyManager::class)->getPrivateKey());
        $accessTokenRepository->persistNewAccessToken($accessToken);
        return (string)$accessToken;
    }

    /**
     * @return array<string, mixed>
     */
    private function whoami(?string $bearer): array
    {
        $this->resetAuthenticationState();
        $request = new ServerRequest('GET', 'http://localhost/test/neos-oauth/whoami', $bearer !== null ? ['Authorization' => 'Bearer ' . $bearer] : []);
        $response = $this->browser->sendRequest($request);
        self::assertSame(200, $response->getStatusCode(), (string)$response->getBody());
        return json_decode((string)$response->getBody(), true, flags: JSON_THROW_ON_ERROR);
    }

    /**
     * The browser runs all requests in one process: forget the previous request's authentication
     */
    private function resetAuthenticationState(): void
    {
        $this->inject($this->objectManager->get(AuthenticationManagerInterface::class), 'isAuthenticated', null);
        foreach ($this->objectManager->get(TokenAndProviderFactoryInterface::class)->getTokens() as $token) {
            if ($token instanceof BearerToken) {
                $this->inject($token, 'credentials', ['bearer' => '']);
            }
        }
    }
}
