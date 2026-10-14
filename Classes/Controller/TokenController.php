<?php
declare(strict_types=1);

namespace Neos\OAuth\Controller;

use GuzzleHttp\Psr7\Response;
use League\OAuth2\Server\Exception\OAuthServerException;
use Neos\Flow\Annotations as Flow;
use Neos\Flow\Log\Utility\LogEnvironment;
use Neos\Flow\Mvc\Controller\ActionController;
use Neos\OAuth\Domain\Model\OAuthClient;
use Neos\OAuth\Domain\Model\TokenType;
use Neos\OAuth\Infrastructure\League\GrantPayloads;
use Neos\OAuth\Infrastructure\League\LeagueResponse;
use Neos\OAuth\Infrastructure\League\Repository\TokenRecords;
use Neos\OAuth\Infrastructure\League\ServerFactory;
use Neos\OAuth\Security\InvalidTarget;
use Neos\OAuth\Security\IssuerNotConfigured;
use Neos\OAuth\Security\ProtectedResources;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;

/**
 * The token endpoint (RFC 6749 section 3.2)
 *
 * Tokens are bound to the resources a client names in "resource" parameters (RFC 8707). A code or refresh token passes
 * its audience on to the tokens it is exchanged for, which a client can narrow down but not widen
 */
class TokenController extends ActionController
{
    #[Flow\Inject]
    protected ServerFactory $serverFactory;

    #[Flow\Inject]
    protected ProtectedResources $protectedResources;

    #[Flow\Inject]
    protected TokenRecords $tokenRecords;

    #[Flow\Inject]
    protected GrantPayloads $grantPayloads;

    /**
     * Clients authenticate with their credentials, not with a session
     */
    #[Flow\SkipCsrfProtection]
    public function tokenAction(): ResponseInterface
    {
        $httpRequest = $this->request->getHttpRequest();
        try {
            $audience = $this->audience($httpRequest);
            return $this->tokenRecords->withAudience($audience, fn () => LeagueResponse::rewound(
                $this->serverFactory->getAuthorizationServer()->respondToAccessTokenRequest($httpRequest, new Response())
            ));
        } catch (OAuthServerException $exception) {
            return LeagueResponse::rewound($exception->generateHttpResponse(new Response()));
        } catch (\Throwable $exception) {
            $this->logger->error(sprintf('OAuth token request failed: %s', $exception->getMessage()), LogEnvironment::fromMethodName(__METHOD__) + ['exception' => $exception]);
            return LeagueResponse::rewound(OAuthServerException::serverError('The token could not be issued')->generateHttpResponse(new Response()));
        }
    }

    /**
     * The audience of the tokens to issue: the requested resources, or else those of the presented code or refresh token
     *
     * @return list<string>
     * @throws OAuthServerException
     */
    private function audience(ServerRequestInterface $httpRequest): array
    {
        $parameters = (array)$httpRequest->getParsedBody();
        $granted = match ($parameters['grant_type'] ?? null) {
            OAuthClient::GRANT_AUTHORIZATION_CODE => $this->grantedAudience($this->grantPayloads->authCodeIdentifier((string)($parameters['code'] ?? '')), TokenType::AUTH_CODE),
            OAuthClient::GRANT_REFRESH_TOKEN => $this->grantedAudience($this->grantPayloads->refreshTokenIdentifier((string)($parameters['refresh_token'] ?? '')), TokenType::REFRESH_TOKEN),
            // client credentials: any resource
            default => [],
        };
        try {
            $requested = $this->protectedResources->audienceFor(self::resourceIndicators($httpRequest));
        } catch (InvalidTarget | IssuerNotConfigured $exception) {
            throw self::invalidTarget($exception->getMessage());
        }
        if ($requested === []) {
            return $granted;
        }
        if ($granted !== [] && array_diff($requested, $granted) !== []) {
            throw self::invalidTarget(sprintf('The grant only covers %s', implode(', ', $granted)));
        }
        return $requested;
    }

    /**
     * @return list<string>
     */
    private function grantedAudience(?string $identifier, TokenType $type): array
    {
        return $identifier !== null ? $this->tokenRecords->audienceOf($identifier, $type) : [];
    }

    /**
     * @return list<string>
     */
    private static function resourceIndicators(ServerRequestInterface $httpRequest): array
    {
        // from the raw body, since the parsed one keeps only the last of repeated parameters
        $indicators = ProtectedResources::indicatorsIn((string)$httpRequest->getBody());
        if ($indicators !== []) {
            return $indicators;
        }
        $resource = ((array)$httpRequest->getParsedBody())['resource'] ?? [];
        return array_values(array_filter((array)$resource, static fn ($value) => is_string($value) && $value !== ''));
    }

    private static function invalidTarget(string $hint): OAuthServerException
    {
        return new OAuthServerException('The requested resource is invalid, unknown, or not covered by the grant.', 0, 'invalid_target', 400, $hint);
    }
}
