<?php
declare(strict_types=1);

namespace Neos\OAuth\Infrastructure\League\Entity;

use League\OAuth2\Server\Entities\RefreshTokenEntityInterface;
use League\OAuth2\Server\Entities\Traits\EntityTrait;
use League\OAuth2\Server\Entities\Traits\RefreshTokenTrait;
use Neos\Flow\Annotations as Flow;

#[Flow\Proxy(false)]
final class RefreshTokenEntity implements RefreshTokenEntityInterface
{
    use EntityTrait;
    use RefreshTokenTrait;
}
