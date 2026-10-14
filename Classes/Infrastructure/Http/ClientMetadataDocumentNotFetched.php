<?php
declare(strict_types=1);

namespace Neos\OAuth\Infrastructure\Http;

use Neos\Flow\Annotations as Flow;

/**
 * The document could not be fetched
 *
 * Temporary failures (network errors, timeouts, server errors) may go away by themselves, so a client whose document
 * was fetched before stays usable for a while. The others (not found, refused address, too large) are definite
 */
#[Flow\Proxy(false)]
final class ClientMetadataDocumentNotFetched extends \RuntimeException
{
    private bool $temporary = false;

    public static function temporarily(string $message, int $code): self
    {
        $exception = new self($message, $code);
        $exception->temporary = true;
        return $exception;
    }

    public function isTemporary(): bool
    {
        return $this->temporary;
    }
}
