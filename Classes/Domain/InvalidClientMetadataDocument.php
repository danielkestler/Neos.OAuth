<?php
declare(strict_types=1);

namespace Neos\OAuth\Domain;

use Neos\Flow\Annotations as Flow;

/**
 * A client ID that is a URL cannot be used: it is no valid client ID URL, its metadata document cannot be fetched or is
 * invalid, or client ID metadata documents are disabled. The message tells the client's developer what is wrong
 */
#[Flow\Proxy(false)]
final class InvalidClientMetadataDocument extends \RuntimeException
{
}
