<?php
declare(strict_types=1);

namespace Neos\OAuth\Tests\Functional\Domain;

use Neos\Flow\Tests\FunctionalTestCase;
use Neos\OAuth\Domain\ClientRegistration;
use Neos\OAuth\Domain\Repository\OAuthClientRepository;
use PHPUnit\Framework\Attributes\Test;

class ClientRegistrationTest extends FunctionalTestCase
{
    protected static $testablePersistenceEnabled = true;

    #[Test]
    public function registersPublicClientsWithAllScopesByDefault(): void
    {
        $secret = $this->registration()->register('spa', 'SPA', ['https://example.com/callback'], ['authorization_code'], null, false, true, null);

        self::assertNull($secret);
        $client = $this->objectManager->get(OAuthClientRepository::class)->findOneByClientIdentifier('spa');
        self::assertFalse($client->isConfidential());
        self::assertTrue($client->isFirstParty());
        self::assertContains('neos.oauth.test', $client->getScopes());
    }

    #[Test]
    public function confidentialClientsGetASecretThatIsOnlyStoredHashed(): void
    {
        $secret = $this->registration()->register('app', 'App', ['https://example.com/callback'], ['authorization_code'], ['neos.oauth.test'], true, false, null);

        self::assertIsString($secret);
        $client = $this->objectManager->get(OAuthClientRepository::class)->findOneByClientIdentifier('app');
        self::assertTrue($client->validateSecret($secret));
    }

    /**
     * @return iterable<string, array{0: list<string>, 1: list<string>|null, 2: int}>
     */
    public static function invalidRegistrations(): iterable
    {
        yield 'plain http' => [['http://example.com/cb'], null, 1790100044];
        yield 'fragment' => [['https://example.com/cb#x'], null, 1790100044];
        yield 'javascript' => [['javascript:alert(1)'], null, 1790100044];
        yield 'unknown scope' => [['https://example.com/cb'], ['unknown'], 1790100041];
    }

    /**
     * @param list<string> $redirectUris
     * @param list<string>|null $scopes
     */
    #[Test]
    #[\PHPUnit\Framework\Attributes\DataProvider('invalidRegistrations')]
    public function rejectsInvalidRegistrations(array $redirectUris, ?array $scopes, int $expectedCode): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionCode($expectedCode);
        $this->registration()->register('client', 'Client', $redirectUris, ['authorization_code'], $scopes, false, false, null);
    }

    private function registration(): ClientRegistration
    {
        return $this->objectManager->get(ClientRegistration::class);
    }
}
