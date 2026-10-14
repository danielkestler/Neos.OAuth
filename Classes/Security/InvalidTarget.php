<?php
declare(strict_types=1);

namespace Neos\OAuth\Security;

use Neos\Flow\Annotations as Flow;

/**
 * A client asked for a token for a resource (RFC 8707 resource indicator) that is no protected resource, or that the
 * grant it presents doesn't cover
 */
#[Flow\Proxy(false)]
final class InvalidTarget extends \RuntimeException
{
}
