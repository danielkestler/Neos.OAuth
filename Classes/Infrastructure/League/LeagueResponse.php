<?php
declare(strict_types=1);

namespace Neos\OAuth\Infrastructure\League;

use Psr\Http\Message\ResponseInterface;

/**
 * league writes its responses into the body stream and leaves the pointer at the end, but Flow emits the body from
 * the current position
 */
final class LeagueResponse
{
    public static function rewound(ResponseInterface $response): ResponseInterface
    {
        $body = $response->getBody();
        if ($body->isSeekable()) {
            $body->rewind();
        }
        return $response;
    }
}
