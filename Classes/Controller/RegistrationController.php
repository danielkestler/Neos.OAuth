<?php
declare(strict_types=1);

namespace Neos\OAuth\Controller;

use GuzzleHttp\Psr7\Response;
use Neos\Flow\Annotations as Flow;
use Neos\Flow\Mvc\Controller\ActionController;
use Neos\OAuth\Domain\ClientRegistration;
use Neos\OAuth\Domain\Model\OAuthClient;
use Neos\OAuth\Security\AuthorizationServerMetadata;
use Psr\Http\Message\ResponseInterface;

/**
 * Dynamic client registration (RFC 7591), e.g. for MCP clients
 *
 * Only public clients (PKCE, no secret) can register themselves, confidential ones are created with
 * ./flow oauth:createclient. A registered client gets no permissions of its own: every token acts as the user who
 * approved it, and it is never first party, so the user is always asked for consent
 */
class RegistrationController extends ActionController
{
    private const array GRANT_TYPES = [OAuthClient::GRANT_AUTHORIZATION_CODE, OAuthClient::GRANT_REFRESH_TOKEN];

    #[Flow\Inject]
    protected ClientRegistration $clientRegistration;

    #[Flow\Inject]
    protected AuthorizationServerMetadata $authorizationServer;

    /**
     * Anonymous clients without a session
     */
    #[Flow\SkipCsrfProtection]
    public function registerAction(): ResponseInterface
    {
        if ($this->authorizationServer->registrationUrl() === null) {
            return self::error(403, 'access_denied', 'Dynamic client registration is disabled');
        }
        try {
            $metadata = json_decode((string)$this->request->getHttpRequest()->getBody(), true, flags: JSON_THROW_ON_ERROR);
        } catch (\JsonException) {
            $metadata = null;
        }
        if (!is_array($metadata) || array_is_list($metadata) && $metadata !== []) {
            return self::error(400, 'invalid_client_metadata', 'The request body must be a JSON object');
        }

        $redirectUris = $metadata['redirect_uris'] ?? null;
        if (!is_array($redirectUris) || $redirectUris === [] || !array_is_list($redirectUris) || array_filter($redirectUris, 'is_string') !== $redirectUris) {
            return self::error(400, 'invalid_redirect_uri', 'redirect_uris must be a non-empty array of strings');
        }
        if (($metadata['token_endpoint_auth_method'] ?? 'none') !== 'none') {
            return self::error(400, 'invalid_client_metadata', 'Only public clients (token_endpoint_auth_method "none") can register, confidential clients are created by an administrator');
        }
        $grantTypes = $metadata['grant_types'] ?? self::GRANT_TYPES;
        if (!is_array($grantTypes) || !in_array(OAuthClient::GRANT_AUTHORIZATION_CODE, $grantTypes, true) || array_diff($grantTypes, self::GRANT_TYPES) !== []) {
            return self::error(400, 'invalid_client_metadata', sprintf('grant_types must contain "%s" and may contain "%s" only', OAuthClient::GRANT_AUTHORIZATION_CODE, OAuthClient::GRANT_REFRESH_TOKEN));
        }
        if (($metadata['response_types'] ?? ['code']) !== ['code']) {
            return self::error(400, 'invalid_client_metadata', 'response_types must be ["code"]');
        }
        $scope = $metadata['scope'] ?? null;
        if ($scope !== null && !is_string($scope)) {
            return self::error(400, 'invalid_client_metadata', 'scope must be a string of space separated scopes');
        }
        $scopes = array_values(array_unique(array_filter(explode(' ', (string)$scope), static fn (string $scope) => $scope !== ''))) ?: null;
        $name = $metadata['client_name'] ?? null;
        $name = is_string($name) && trim($name) !== '' ? mb_substr(trim($name), 0, 200) : 'Dynamically registered client';

        $identifier = bin2hex(random_bytes(16));
        $grantTypes = array_values(array_unique($grantTypes));
        try {
            $this->clientRegistration->register($identifier, $name, $redirectUris, $grantTypes, $scopes, false, false, null);
        } catch (\InvalidArgumentException $exception) {
            return self::error(400, $exception->getCode() === ClientRegistration::INVALID_REDIRECT_URI ? 'invalid_redirect_uri' : 'invalid_client_metadata', $exception->getMessage());
        }

        return self::json(201, [
            'client_id' => $identifier,
            'client_id_issued_at' => time(),
            'client_name' => $name,
            'redirect_uris' => $redirectUris,
            'grant_types' => $grantTypes,
            'response_types' => ['code'],
            'token_endpoint_auth_method' => 'none',
            'scope' => implode(' ', $scopes ?? $this->clientRegistration->defaultScopes()),
        ]);
    }

    private static function error(int $status, string $error, string $description): ResponseInterface
    {
        return self::json($status, ['error' => $error, 'error_description' => $description]);
    }

    /**
     * @param array<string, mixed> $body
     */
    private static function json(int $status, array $body): ResponseInterface
    {
        return new Response($status, [
            'Content-Type' => 'application/json',
            'Cache-Control' => 'no-store',
        ], json_encode($body, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES));
    }
}
