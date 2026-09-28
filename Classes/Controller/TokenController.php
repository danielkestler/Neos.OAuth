<?php
declare(strict_types=1);

namespace Neos\OAuth\Controller;

use GuzzleHttp\Psr7\Response;
use League\OAuth2\Server\Exception\OAuthServerException;
use Neos\Flow\Annotations as Flow;
use Neos\Flow\Log\Utility\LogEnvironment;
use Neos\Flow\Mvc\Controller\ActionController;
use Neos\OAuth\Infrastructure\League\LeagueResponse;
use Neos\OAuth\Infrastructure\League\ServerFactory;
use Psr\Http\Message\ResponseInterface;

/**
 * The token endpoint (RFC 6749 section 3.2)
 */
class TokenController extends ActionController
{
    #[Flow\Inject]
    protected ServerFactory $serverFactory;

    /**
     * Clients authenticate with their credentials, not with a session
     */
    #[Flow\SkipCsrfProtection]
    public function tokenAction(): ResponseInterface
    {
        try {
            return LeagueResponse::rewound($this->serverFactory->getAuthorizationServer()->respondToAccessTokenRequest($this->request->getHttpRequest(), new Response()));
        } catch (OAuthServerException $exception) {
            return LeagueResponse::rewound($exception->generateHttpResponse(new Response()));
        } catch (\Throwable $exception) {
            $this->logger->error(sprintf('OAuth token request failed: %s', $exception->getMessage()), LogEnvironment::fromMethodName(__METHOD__) + ['exception' => $exception]);
            return LeagueResponse::rewound(OAuthServerException::serverError('The token could not be issued')->generateHttpResponse(new Response()));
        }
    }
}
