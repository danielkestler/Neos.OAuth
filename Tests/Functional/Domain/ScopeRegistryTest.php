<?php
declare(strict_types=1);

namespace Neos\OAuth\Tests\Functional\Domain;

use Neos\Flow\Tests\FunctionalTestCase;
use Neos\OAuth\Domain\ScopeRegistry;
use Neos\Utility\ObjectAccess;
use PHPUnit\Framework\Attributes\Test;

class ScopeRegistryTest extends FunctionalTestCase
{
    #[Test]
    public function groupsTheScopesByPrefixInTheConfiguredOrder(): void
    {
        $scopeRegistry = new ScopeRegistry($this->objectManager);
        ObjectAccess::setProperty($scopeRegistry, 'scopeGroups', [
            'neos' => ['label' => 'Neos', 'icon' => 'resource://Neos.OAuth/Public/neos.svg', 'position' => 20],
            'first' => ['label' => 'First', 'position' => 10],
            'removed' => null,
        ], true);

        self::assertSame([
            [
                'label' => 'First',
                'icon' => null,
                'scopes' => [['identifier' => 'first.read', 'description' => 'first.read']],
            ],
            [
                'label' => 'Neos',
                'icon' => 'resource://Neos.OAuth/Public/neos.svg',
                'scopes' => [
                    ['identifier' => 'neos.oauth.test', 'description' => 'Scope of the functional tests'],
                    ['identifier' => 'neos.oauth.provided', 'description' => 'Scope of a scope provider'],
                ],
            ],
            [
                'label' => 'removed',
                'icon' => null,
                'scopes' => [['identifier' => 'removed.read', 'description' => 'removed.read']],
            ],
        ], $scopeRegistry->group(['neos.oauth.test', 'first.read', 'removed.read', 'neos.oauth.provided']));
    }
}
