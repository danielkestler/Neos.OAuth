<?php
declare(strict_types=1);

namespace Neos\OAuth\Tests\Functional\Domain;

use Neos\Flow\Tests\FunctionalTestCase;
use Neos\OAuth\Domain\ClientDirectory;
use Neos\OAuth\Domain\ClientRegistration;
use PHPUnit\Framework\Attributes\Test;

class ClientDirectoryTest extends FunctionalTestCase
{
    protected static $testablePersistenceEnabled = true;

    #[Test]
    public function declaredClientsNeedNoRegistration(): void
    {
        $client = $this->objectManager->get(ClientDirectory::class)->find('declared-spa');

        self::assertNotNull($client);
        self::assertSame('Declared SPA', $client->getName());
        self::assertFalse($client->isConfidential());
        self::assertTrue($client->isFirstParty());
        self::assertSame(['http://localhost/callback'], $client->getRedirectUris());
        self::assertSame(['authorization_code', 'refresh_token'], $client->getGrantTypes());
        self::assertContains('neos.oauth.test', $client->getScopes());
    }

    #[Test]
    public function invalidDeclaredClientsAreNotUsable(): void
    {
        self::assertNull($this->objectManager->get(ClientDirectory::class)->find('invalid-declared'));
    }

    #[Test]
    public function declaredIdentifiersCannotBeRegistered(): void
    {
        $this->expectExceptionCode(1790100040);
        $this->objectManager->get(ClientRegistration::class)->register('declared-spa', 'Other', ['https://example.com/cb'], ['authorization_code'], null, false, false, null);
    }
}
