<?php
declare(strict_types=1);

namespace Neos\OAuth\Infrastructure\League\Entity;

use League\OAuth2\Server\Entities\ClientEntityInterface;
use League\OAuth2\Server\Entities\Traits\ClientTrait;
use League\OAuth2\Server\Entities\Traits\EntityTrait;
use Neos\Flow\Annotations as Flow;
use Neos\OAuth\Domain\Model\OAuthClient;

#[Flow\Proxy(false)]
final class ClientEntity implements ClientEntityInterface
{
    use EntityTrait;
    use ClientTrait;

    /**
     * @param list<string> $grantTypes
     * @param list<string> $scopes
     */
    private function __construct(
        string $identifier,
        string $name,
        array $redirectUris,
        bool $isConfidential,
        public readonly array $grantTypes,
        public readonly array $scopes,
        public readonly bool $firstParty,
        public readonly ?string $accountIdentifier,
    ) {
        $this->identifier = $identifier;
        $this->name = $name;
        $this->redirectUri = $redirectUris;
        $this->isConfidential = $isConfidential;
    }

    public static function fromModel(OAuthClient $client): self
    {
        return new self(
            $client->getIdentifier(),
            $client->getName(),
            $client->getRedirectUris(),
            $client->isConfidential(),
            $client->getGrantTypes(),
            $client->getScopes(),
            $client->isFirstParty(),
            $client->getAccountIdentifier(),
        );
    }

    public function allowsGrantType(string $grantType): bool
    {
        return in_array($grantType, $this->grantTypes, true);
    }
}
