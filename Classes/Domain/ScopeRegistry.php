<?php
declare(strict_types=1);

namespace Neos\OAuth\Domain;

use Neos\Flow\Annotations as Flow;
use Neos\Flow\ObjectManagement\ObjectManagerInterface;

/**
 * The scopes clients can request: configured in Neos.OAuth.scopes or contributed by the Neos.OAuth.scopeProviders of
 * the packages that accept the tokens
 */
#[Flow\Scope('singleton')]
final class ScopeRegistry
{
    /**
     * @var array<string, string|null> scope identifier => description, null removes a scope
     */
    #[Flow\InjectConfiguration(path: 'scopes', package: 'Neos.OAuth')]
    protected array $scopes = [];

    /**
     * @var array<string, class-string<ScopeProvider>|null> key => class name, null removes a provider
     */
    #[Flow\InjectConfiguration(path: 'scopeProviders', package: 'Neos.OAuth')]
    protected array $scopeProviders = [];

    /**
     * @var array<string, string>|null
     */
    private ?array $descriptions = null;

    public function __construct(
        private readonly ObjectManagerInterface $objectManager,
    ) {
    }

    public function isKnown(string $scope): bool
    {
        return isset($this->descriptions()[$scope]);
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
        if ($this->descriptions !== null) {
            return $this->descriptions;
        }
        $descriptions = [];
        foreach ($this->scopes as $identifier => $description) {
            if ($description !== null) {
                $descriptions[(string)$identifier] = (string)$description;
            }
        }
        foreach ($this->scopeProviders as $key => $className) {
            if ($className === null) {
                continue;
            }
            foreach ($this->provider($className)->scopes() as $identifier => $description) {
                if (isset($descriptions[$identifier])) {
                    throw new \LogicException(sprintf('The scope "%s" of the scope provider "%s" is already registered', $identifier, $key), 1790100070);
                }
                $descriptions[$identifier] = $description;
            }
        }
        return $this->descriptions = $descriptions;
    }

    public function describe(string $scope): string
    {
        return $this->descriptions()[$scope] ?? $scope;
    }

    /**
     * @param class-string<ScopeProvider> $className
     */
    public function provider(string $className): ScopeProvider
    {
        $provider = $this->objectManager->get($className);
        if (!$provider instanceof ScopeProvider) {
            throw new \LogicException(sprintf('The scope provider "%s" does not implement %s', $className, ScopeProvider::class), 1790100071);
        }
        return $provider;
    }
}
