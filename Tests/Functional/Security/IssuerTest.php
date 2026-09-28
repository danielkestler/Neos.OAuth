<?php
declare(strict_types=1);

namespace Neos\OAuth\Tests\Functional\Security;

use Neos\Flow\Tests\FunctionalTestCase;
use Neos\Neos\Domain\Model\Domain;
use Neos\Neos\Domain\Model\Site;
use Neos\Neos\Domain\Repository\DomainRepository;
use Neos\Neos\Domain\Repository\SiteRepository;
use Neos\OAuth\Security\AuthorizationServerMetadata;
use Neos\OAuth\Security\IssuerNotConfigured;
use PHPUnit\Framework\Attributes\Test;

class IssuerTest extends FunctionalTestCase
{
    protected static $testablePersistenceEnabled = true;

    #[Test]
    public function theIssuerSettingComesFirst(): void
    {
        $metadata = $this->metadata(issuer: 'https://issuer.example.com/', baseUri: 'https://base.example.com');

        self::assertSame('https://issuer.example.com', $metadata->issuer());
        self::assertSame('Neos.OAuth.issuer', $metadata->issuerSource());
    }

    #[Test]
    public function fallsBackToTheBaseUri(): void
    {
        self::assertSame('https://base.example.com', $this->metadata(issuer: null, baseUri: 'https://base.example.com')->issuer());
    }

    #[Test]
    public function fallsBackToThePrimaryDomainOfTheDefaultSite(): void
    {
        $site = new Site('oauthtest');
        $site->setSiteResourcesPackageKey('Neos.OAuth');
        $site->setState(Site::STATE_ONLINE);
        $this->objectManager->get(SiteRepository::class)->add($site);
        $domain = new Domain();
        $domain->setHostname('neos.example.com');
        $domain->setScheme('https');
        $domain->setPort(8443);
        $domain->setSite($site);
        $this->objectManager->get(DomainRepository::class)->add($domain);
        $site->setPrimaryDomain($domain);
        $this->persistenceManager->persistAll();

        $metadata = $this->metadata(issuer: null, baseUri: null);

        self::assertSame('https://neos.example.com:8443', $metadata->issuer());
        self::assertSame('the primary domain of the site "oauthtest"', $metadata->issuerSource());
    }

    #[Test]
    public function isUnknownWithoutConfigurationOrSiteDomain(): void
    {
        $this->expectException(IssuerNotConfigured::class);
        $this->metadata(issuer: null, baseUri: null)->issuer();
    }

    private function metadata(?string $issuer, ?string $baseUri): AuthorizationServerMetadata
    {
        $metadata = new AuthorizationServerMetadata(...[
            $this->objectManager->get(\Neos\OAuth\Domain\ScopeRegistry::class),
            $this->objectManager->get(SiteRepository::class),
        ]);
        $this->inject($metadata, 'issuer', $issuer);
        $this->inject($metadata, 'baseUri', $baseUri);
        return $metadata;
    }
}
