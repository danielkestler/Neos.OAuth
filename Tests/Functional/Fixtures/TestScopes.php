<?php
declare(strict_types=1);

namespace Neos\OAuth\Tests\Functional\Fixtures;

use Neos\OAuth\Domain\ScopeProvider;

final class TestScopes implements ScopeProvider
{
    public function scopes(): array
    {
        return ['neos.oauth.provided' => 'Scope of a scope provider'];
    }
}
