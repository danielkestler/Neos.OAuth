<?php
declare(strict_types=1);

namespace Neos\OAuth\Infrastructure\League\Entity;

use League\OAuth2\Server\Entities\Traits\EntityTrait;
use League\OAuth2\Server\Entities\UserEntityInterface;
use Neos\Flow\Annotations as Flow;

/**
 * The resource owner: its identifier is the Flow account identifier and becomes the token's "sub" claim
 */
#[Flow\Proxy(false)]
final class UserEntity implements UserEntityInterface
{
    use EntityTrait;

    public function __construct(string $accountIdentifier)
    {
        $this->identifier = $accountIdentifier;
    }
}
