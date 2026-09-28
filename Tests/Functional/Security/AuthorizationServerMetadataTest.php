<?php
declare(strict_types=1);

namespace Neos\OAuth\Tests\Functional\Security;

use GuzzleHttp\Psr7\Uri;
use Neos\Flow\Mvc\Routing\Dto\ResolveContext;
use Neos\Flow\Mvc\Routing\Dto\RouteParameters;
use Neos\Flow\Mvc\Routing\RouterInterface;
use Neos\Flow\Tests\FunctionalTestCase;
use Neos\OAuth\Security\AuthorizationServerMetadata;
use PHPUnit\Framework\Attributes\Test;

class AuthorizationServerMetadataTest extends FunctionalTestCase
{
    #[Test]
    public function urlsMatchTheRoutes(): void
    {
        $metadata = $this->objectManager->get(AuthorizationServerMetadata::class);

        self::assertSame($metadata->tokenUrl(), $this->resolve('Token', 'token', 'json'));
        self::assertSame($metadata->authorizationUrl(), $this->resolve('Authorize', 'authorize', 'html'));
    }

    private function resolve(string $controller, string $action, string $format): string
    {
        $uri = $this->objectManager->get(RouterInterface::class)->resolve(new ResolveContext(
            new Uri('http://localhost/'),
            ['@package' => 'Neos.OAuth', '@controller' => $controller, '@action' => $action, '@format' => $format],
            false,
            '',
            RouteParameters::createEmpty(),
        ));
        return '/' . ltrim((string)$uri, '/');
    }
}
