<?php
declare(strict_types=1);

namespace Neos\OAuth\Security;

use Neos\Flow\Annotations as Flow;

#[Flow\Proxy(false)]
final class IssuerNotConfigured extends \RuntimeException
{
}
