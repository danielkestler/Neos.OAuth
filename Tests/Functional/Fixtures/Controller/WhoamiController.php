<?php
declare(strict_types=1);

namespace Neos\OAuth\Tests\Functional\Fixtures\Controller;

use GuzzleHttp\Psr7\Response;
use Neos\Flow\Annotations as Flow;
use Neos\Flow\Mvc\Controller\ActionController;
use Neos\Flow\Security\Context as SecurityContext;
use Neos\OAuth\Security\OAuthContext;
use Psr\Http\Message\ResponseInterface;

/**
 * Reports what the Neos.OAuth:Bearer provider authenticated
 */
class WhoamiController extends ActionController
{
    #[Flow\Inject]
    protected OAuthContext $oauthContext;

    #[Flow\Inject]
    protected SecurityContext $securityContext;

    public function indexAction(): ResponseInterface
    {
        $grant = $this->oauthContext->authenticatedGrant();
        $result = $grant === null ? ['authenticated' => false] : [
            'authenticated' => true,
            'account' => $grant->account->getAccountIdentifier(),
            'client' => $grant->clientIdentifier,
            'scopes' => $grant->scopes,
            'roles' => array_keys($this->securityContext->getRoles()),
        ];
        return new Response(200, ['Content-Type' => 'application/json'], json_encode($result, JSON_THROW_ON_ERROR));
    }
}
