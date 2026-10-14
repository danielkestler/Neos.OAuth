<?php
declare(strict_types=1);

namespace Neos\OAuth\Infrastructure\Http;

use Neos\Flow\Annotations as Flow;

/**
 * The body of a fetched document and how long the server allows to cache it
 */
#[Flow\Proxy(false)]
final readonly class FetchedDocument
{
    /**
     * @param int|null $maxAge seconds from Cache-Control: max-age, null if the response doesn't say
     */
    public function __construct(
        public string $body,
        public ?int $maxAge,
    ) {
    }

    /**
     * The max-age of a Cache-Control header, 0 for no-store and no-cache
     */
    public static function maxAgeOf(string $cacheControl): ?int
    {
        if (preg_match('/(?:^|,)\s*(?:no-store|no-cache)\s*(?:,|$)/i', $cacheControl) === 1) {
            return 0;
        }
        return preg_match('/(?:^|,)\s*max-age\s*=\s*"?(\d+)"?\s*(?:,|$)/i', $cacheControl, $matches) === 1 ? (int)min($matches[1], PHP_INT_MAX) : null;
    }
}
