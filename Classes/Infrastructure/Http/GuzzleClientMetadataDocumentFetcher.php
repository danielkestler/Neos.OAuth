<?php
declare(strict_types=1);

namespace Neos\OAuth\Infrastructure\Http;

use GuzzleHttp\Client;
use GuzzleHttp\Exception\GuzzleException;
use GuzzleHttp\Exception\RequestException;
use GuzzleHttp\Handler\CurlHandler;
use GuzzleHttp\HandlerStack;
use Neos\Flow\Annotations as Flow;
use Psr\Http\Message\ResponseInterface;

/**
 * Fetches client metadata documents with Guzzle, guarded against server-side request forgery
 *
 * The URL comes from anyone who opens the authorization endpoint, so the request must not reach internal services:
 * https only, no redirects, no proxy, and the host must resolve to public addresses only. curl is pinned to the
 * checked addresses (CURLOPT_RESOLVE), so a second DNS answer cannot point it elsewhere (DNS rebinding). That is why
 * the curl handler is used explicitly: Guzzle would hand streamed requests to its PHP stream handler, which ignores
 * curl options. The response is limited in time and size: curl aborts beyond the size limit (CURLOPT_MAXFILESIZE,
 * also without Content-Length since curl 8.4), and at most the limit is read from the body
 */
#[Flow\Scope('singleton')]
final class GuzzleClientMetadataDocumentFetcher implements ClientMetadataDocumentFetcher
{
    /**
     * Address ranges that are not reachable on the public internet or have a special purpose (RFC 6890 and its
     * updates), as [network, prefix length]. IPv6 is further limited to global unicast (2000::/3)
     */
    private const array NON_PUBLIC_RANGES = [
        ['0.0.0.0', 8], ['10.0.0.0', 8], ['100.64.0.0', 10], ['127.0.0.0', 8], ['169.254.0.0', 16],
        ['172.16.0.0', 12], ['192.0.0.0', 24], ['192.0.2.0', 24], ['192.88.99.0', 24], ['192.168.0.0', 16],
        ['198.18.0.0', 15], ['198.51.100.0', 24], ['203.0.113.0', 24], ['224.0.0.0', 4], ['240.0.0.0', 4],
        // IETF protocol assignments incl. Teredo, documentation, 6to4 (embeds IPv4 addresses)
        ['2001::', 23], ['2001:db8::', 32], ['2002::', 16],
    ];

    private const int CURLE_FILESIZE_EXCEEDED = 63;

    /**
     * @var array{allowPrivateNetworks?: bool, timeout?: int, maximumSize?: int}
     */
    #[Flow\InjectConfiguration(path: 'clientIdMetadataDocuments', package: 'Neos.OAuth')]
    protected array $settings = [];

    public function fetch(string $url): FetchedDocument
    {
        $parts = parse_url($url);
        if ($parts === false || strtolower($parts['scheme'] ?? '') !== 'https' || !isset($parts['host'])) {
            throw new ClientMetadataDocumentNotFetched(sprintf('"%s" is no https URL', $url), 1792100001);
        }
        $host = trim($parts['host'], '[]');
        $port = $parts['port'] ?? 443;
        $addresses = $this->resolve($host);
        if (!($this->settings['allowPrivateNetworks'] ?? false)) {
            foreach ($addresses as $address) {
                if (!self::isPublicAddress($address)) {
                    throw new ClientMetadataDocumentNotFetched(sprintf('The host "%s" resolves to the non-public address %s', $host, $address), 1792100002);
                }
            }
        }

        $maximumSize = (int)($this->settings['maximumSize'] ?? 65536);
        $timeout = (int)($this->settings['timeout'] ?? 5);
        $client = new Client(['handler' => HandlerStack::create(new CurlHandler())]);
        try {
            $response = $client->request('GET', $url, [
                'allow_redirects' => false,
                'http_errors' => false,
                'timeout' => $timeout,
                'connect_timeout' => $timeout,
                'verify' => true,
                'protocols' => ['https'],
                // no proxy, not even one from the environment: it would resolve the host itself
                'proxy' => ['https' => '', 'no' => ['*']],
                'headers' => ['Accept' => 'application/json', 'User-Agent' => 'Neos.OAuth client metadata fetcher'],
                'curl' => [
                    // pinned to the checked addresses
                    CURLOPT_RESOLVE => [sprintf('%s:%d:%s', $host, $port, implode(',', array_map(static fn (string $address) => str_contains($address, ':') ? '[' . $address . ']' : $address, $addresses)))],
                    CURLOPT_MAXFILESIZE => $maximumSize,
                ],
            ]);
        } catch (RequestException $exception) {
            if (($exception->getHandlerContext()['errno'] ?? null) === self::CURLE_FILESIZE_EXCEEDED) {
                throw new ClientMetadataDocumentNotFetched(sprintf('The document is larger than %d bytes', $maximumSize), 1792100003, $exception);
            }
            throw ClientMetadataDocumentNotFetched::temporarily(sprintf('The request failed: %s', $exception->getMessage()), 1792100004);
        } catch (GuzzleException $exception) {
            throw ClientMetadataDocumentNotFetched::temporarily(sprintf('The request failed: %s', $exception->getMessage()), 1792100004);
        }
        return new FetchedDocument(self::body($response, $maximumSize), FetchedDocument::maxAgeOf($response->getHeaderLine('Cache-Control')));
    }

    /**
     * @throws ClientMetadataDocumentNotFetched
     */
    private static function body(ResponseInterface $response, int $maximumSize): string
    {
        $status = $response->getStatusCode();
        if ($status >= 500) {
            throw ClientMetadataDocumentNotFetched::temporarily(sprintf('The server responded with status %d', $status), 1792100005);
        }
        if ($status !== 200) {
            throw new ClientMetadataDocumentNotFetched(sprintf('The server responded with status %d%s', $status, $status >= 300 && $status < 400 ? ', redirects are not followed' : ''), 1792100006);
        }
        $stream = $response->getBody();
        $body = '';
        while (!$stream->eof() && strlen($body) <= $maximumSize) {
            $body .= $stream->read($maximumSize + 1 - strlen($body));
        }
        if (strlen($body) > $maximumSize) {
            throw new ClientMetadataDocumentNotFetched(sprintf('The document is larger than %d bytes', $maximumSize), 1792100003);
        }
        return $body;
    }

    /**
     * Whether an IP address is reachable on the public internet, i.e. no private, loopback, link-local, multicast or
     * otherwise reserved address
     */
    public static function isPublicAddress(string $address): bool
    {
        $packed = @inet_pton($address);
        if ($packed === false) {
            return false;
        }
        if (strlen($packed) === 16) {
            // IPv4-mapped IPv6 addresses are judged as the IPv4 address they map to
            if (str_starts_with($packed, str_repeat("\0", 10) . "\xff\xff")) {
                return self::isPublicAddress((string)inet_ntop(substr($packed, 12)));
            }
            // global unicast only: excludes ::, ::1, unique local, link-local, multicast and NAT64 (64:ff9b::/96)
            if ((ord($packed[0]) & 0xe0) !== 0x20) {
                return false;
            }
        }
        foreach (self::NON_PUBLIC_RANGES as [$network, $prefixLength]) {
            if (self::inRange($packed, (string)inet_pton($network), $prefixLength)) {
                return false;
            }
        }
        return true;
    }

    private static function inRange(string $packed, string $network, int $prefixLength): bool
    {
        if (strlen($packed) !== strlen($network)) {
            return false;
        }
        $bytes = intdiv($prefixLength, 8);
        if (substr($packed, 0, $bytes) !== substr($network, 0, $bytes)) {
            return false;
        }
        $bits = $prefixLength % 8;
        if ($bits === 0) {
            return true;
        }
        $mask = (0xff << (8 - $bits)) & 0xff;
        return (ord($packed[$bytes]) & $mask) === (ord($network[$bytes]) & $mask);
    }

    /**
     * @return non-empty-list<string> the IPv4 and IPv6 addresses of the host
     * @throws ClientMetadataDocumentNotFetched
     */
    private function resolve(string $host): array
    {
        if (filter_var($host, FILTER_VALIDATE_IP) !== false) {
            return [$host];
        }
        $addresses = [];
        foreach (@dns_get_record($host, DNS_A | DNS_AAAA) ?: [] as $record) {
            $address = $record['ip'] ?? $record['ipv6'] ?? null;
            if (is_string($address)) {
                $addresses[] = $address;
            }
        }
        if ($addresses === []) {
            // e.g. /etc/hosts entries, which dns_get_record() doesn't see
            $addresses = @gethostbynamel($host) ?: [];
        }
        if ($addresses === []) {
            throw ClientMetadataDocumentNotFetched::temporarily(sprintf('The host "%s" could not be resolved', $host), 1792100007);
        }
        return array_values(array_unique($addresses));
    }
}
