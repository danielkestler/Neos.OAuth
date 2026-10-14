<?php
declare(strict_types=1);

namespace Neos\OAuth\Infrastructure\Http;

/**
 * Fetches the metadata document of a client that is identified by its URL (OAuth Client ID Metadata Document)
 *
 * An interface so that tests can hand out documents without the network
 */
interface ClientMetadataDocumentFetcher
{
    /**
     * @param string $url an https URL, already checked to be a valid client ID
     * @throws ClientMetadataDocumentNotFetched
     */
    public function fetch(string $url): FetchedDocument;
}
