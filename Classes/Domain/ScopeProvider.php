<?php
declare(strict_types=1);

namespace Neos\OAuth\Domain;

/**
 * Contributes scopes that a package derives from elsewhere, e.g. from its privileges, instead of listing them in
 * Neos.OAuth.scopes
 *
 * Registered in Neos.OAuth.scopeProviders, and usable as the scopeProvider of a protected resource
 */
interface ScopeProvider
{
    /**
     * @return array<string, string> scope identifier => description
     */
    public function scopes(): array;
}
