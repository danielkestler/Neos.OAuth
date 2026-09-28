<?php
declare(strict_types=1);

namespace Neos\OAuth\Domain;

use Neos\Flow\Annotations as Flow;

/**
 * The scopes clients can request: configured in Neos.OAuth.scopes by the packages that accept the tokens
 */
#[Flow\Scope('singleton')]
final class ScopeRegistry
{
    /**
     * @var array<string, string|null> scope identifier => description, null removes a scope
     */
    #[Flow\InjectConfiguration(path: 'scopes', package: 'Neos.OAuth')]
    protected array $scopes = [];

    public function isKnown(string $scope): bool
    {
        return ($this->scopes[$scope] ?? null) !== null;
    }

    /**
     * @return list<string>
     */
    public function identifiers(): array
    {
        return array_keys($this->descriptions());
    }

    /**
     * @return array<string, string> scope identifier => description
     */
    public function descriptions(): array
    {
        $descriptions = [];
        foreach ($this->scopes as $identifier => $description) {
            if ($description !== null) {
                $descriptions[(string)$identifier] = (string)$description;
            }
        }
        return $descriptions;
    }

    public function describe(string $scope): string
    {
        return $this->descriptions()[$scope] ?? $scope;
    }
}
