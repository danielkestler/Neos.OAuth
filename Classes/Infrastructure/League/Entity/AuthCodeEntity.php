<?php
declare(strict_types=1);

namespace Neos\OAuth\Infrastructure\League\Entity;

use League\OAuth2\Server\Entities\AuthCodeEntityInterface;
use League\OAuth2\Server\Entities\Traits\AuthCodeTrait;
use League\OAuth2\Server\Entities\Traits\EntityTrait;
use League\OAuth2\Server\Entities\Traits\TokenEntityTrait;
use Neos\Flow\Annotations as Flow;

#[Flow\Proxy(false)]
final class AuthCodeEntity implements AuthCodeEntityInterface
{
    use EntityTrait;
    use TokenEntityTrait;
    use AuthCodeTrait;
}
