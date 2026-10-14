<?php
declare(strict_types=1);

namespace Neos\OAuth\Domain;

use Neos\Flow\Annotations as Flow;
use Neos\Flow\ObjectManagement\ObjectManagerInterface;
use Neos\Utility\PositionalArraySorter;

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
     * @var array<string, array{label?: string, icon?: string, position?: int|string}|null> scope prefix => group, null removes a group
     */
    #[Flow\InjectConfiguration(path: 'scopeGroups', package: 'Neos.OAuth')]
    protected array $scopeGroups = [];

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
     * Groups the scopes by their prefix, the part before the first dot, as configured in Neos.OAuth.scopeGroups
     *
     * A prefix without a group gets one labeled with the prefix, at the end
     *
     * @param list<string> $scopes
     * @return list<array{label: string, icon: string|null, scopes: list<array{identifier: string, description: string}>}>
     */
    public function group(array $scopes): array
    {
        $groups = [];
        foreach ($scopes as $scope) {
            $prefix = explode('.', $scope, 2)[0];
            $configuration = $this->scopeGroups[$prefix] ?? [];
            $groups[$prefix] ??= [
                'label' => $configuration['label'] ?? $prefix,
                'icon' => $configuration['icon'] ?? null,
                'position' => $configuration['position'] ?? 'end',
                'scopes' => [],
            ];
            $groups[$prefix]['scopes'][] = ['identifier' => $scope, 'description' => $this->describe($scope)];
        }
        return array_values(array_map(
            static fn (array $group) => ['label' => $group['label'], 'icon' => $group['icon'], 'scopes' => $group['scopes']],
            (new PositionalArraySorter($groups))->toArray(),
        ));
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
