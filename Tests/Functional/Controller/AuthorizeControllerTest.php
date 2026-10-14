<?php
declare(strict_types=1);

namespace Neos\OAuth\Tests\Functional\Controller;

use League\OAuth2\Server\Exception\OAuthServerException;
use League\OAuth2\Server\RequestTypes\AuthorizationRequest;
use Neos\Flow\Security\AccountFactory;
use Neos\Flow\Security\AccountRepository;
use Neos\Flow\Tests\FunctionalTestCase;
use Neos\OAuth\Controller\AuthorizeController;
use Neos\OAuth\Infrastructure\League\Repository\ClientRepository;
use Neos\OAuth\Infrastructure\League\Repository\ScopeRepository;
use PHPUnit\Framework\Attributes\Test;
use Psr\Http\Message\ResponseInterface;

/**
 * The redirects of the authorization endpoint, without the login and consent pages
 */
class AuthorizeControllerTest extends FunctionalTestCase
{
    protected static $testablePersistenceEnabled = true;

    private const string REDIRECT_URI = 'http://localhost/callback';

    #[Test]
    public function redirectsWithACodeNameTheIssuer(): void
    {
        $accountFactory = $this->objectManager->get(AccountFactory::class);
        $account = $accountFactory->createAccountWithPassword('editor', 'password', ['Neos.Neos:Editor'], 'Neos.Neos:Backend');
        $this->objectManager->get(AccountRepository::class)->add($account);
        $this->persistenceManager->persistAll();

        $authorizationRequest = new AuthorizationRequest();
        $authorizationRequest->setGrantTypeId('authorization_code');
        $authorizationRequest->setClient($this->objectManager->get(ClientRepository::class)->getClientEntity('declared-spa'));
        $authorizationRequest->setScopes([$this->objectManager->get(ScopeRepository::class)->getScopeEntityByIdentifier('neos.oauth.test')]);
        $authorizationRequest->setRedirectUri(self::REDIRECT_URI);
        $authorizationRequest->setState('the-state');
        $authorizationRequest->setCodeChallenge(str_repeat('a', 43));
        $authorizationRequest->setCodeChallengeMethod('S256');

        $query = $this->redirectQuery($this->callController('complete', $authorizationRequest, [], $account, true));

        self::assertArrayHasKey('code', $query);
        self::assertSame('the-state', $query['state']);
        self::assertSame('http://localhost', $query['iss']);
    }

    #[Test]
    public function redirectsWithAnErrorNameTheIssuer(): void
    {
        $exception = new OAuthServerException('Denied', 9, 'access_denied', 401, null, self::REDIRECT_URI . '?state=the-state');

        $query = $this->redirectQuery($this->callController('errorResponse', $exception));

        self::assertSame('access_denied', $query['error']);
        self::assertSame('the-state', $query['state']);
        self::assertSame('http://localhost', $query['iss']);
    }

    private function callController(string $methodName, mixed ...$arguments): mixed
    {
        $controller = $this->objectManager->get(AuthorizeController::class);
        return (new \ReflectionMethod($controller, $methodName))->invoke($controller, ...$arguments);
    }

    /**
     * @return array<string, string>
     */
    private function redirectQuery(mixed $response): array
    {
        self::assertInstanceOf(ResponseInterface::class, $response);
        $location = $response->getHeaderLine('Location');
        self::assertStringStartsWith(self::REDIRECT_URI . '?', $location);
        parse_str((string)parse_url($location, PHP_URL_QUERY), $query);
        return $query;
    }
}
