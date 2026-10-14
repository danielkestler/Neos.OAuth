<?php
declare(strict_types=1);

namespace Neos\OAuth\Tests\Functional\Fixtures;

use Neos\Flow\Annotations as Flow;
use Neos\OAuth\Infrastructure\Http\ClientMetadataDocumentFetcher;
use Neos\OAuth\Infrastructure\Http\ClientMetadataDocumentNotFetched;
use Neos\OAuth\Infrastructure\Http\FetchedDocument;

/**
 * Hands out the documents a test put in, without the network, see Configuration/Testing/Objects.yaml
 */
#[Flow\Scope('singleton')]
class FakeClientMetadataDocumentFetcher implements ClientMetadataDocumentFetcher
{
    /**
     * @var array<string, FetchedDocument|ClientMetadataDocumentNotFetched>
     */
    private array $responses = [];

    /**
     * @var array<string, int>
     */
    public array $fetches = [];

    /**
     * @param array<string, mixed>|string $document a JSON document, or the raw body
     */
    public function serve(string $url, array|string $document, ?int $maxAge = null): void
    {
        $this->responses[$url] = new FetchedDocument(is_string($document) ? $document : json_encode($document, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES), $maxAge);
    }

    public function fail(string $url, ClientMetadataDocumentNotFetched $exception): void
    {
        $this->responses[$url] = $exception;
    }

    public function reset(): void
    {
        $this->responses = [];
        $this->fetches = [];
    }

    public function fetch(string $url): FetchedDocument
    {
        $this->fetches[$url] = ($this->fetches[$url] ?? 0) + 1;
        $response = $this->responses[$url] ?? new ClientMetadataDocumentNotFetched('The server responded with status 404', 1792199001);
        if ($response instanceof ClientMetadataDocumentNotFetched) {
            throw $response;
        }
        return $response;
    }
}
