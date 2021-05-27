<?php

namespace RFY\JWT\Controller;

/*                                                                          *
 * This script belongs to the Neos Flow package "RFY.JsonApi.Authenticator".*
 *                                                                          *
 *                                                                          */

use Neos\Flow\Annotations as Flow;

use Neos\Flow\I18n\Service;
use Neos\Flow\Mvc\View\JsonView;
use Neos\Flow\Security\Authentication\Controller\AbstractAuthenticationController;
use Neos\Flow\Security\Exception\AuthenticationRequiredException;
use RFY\JWT\Security\Authentication\Factory\TokenFactory;
use Neos\Flow\Mvc\ActionRequest;

/**
 * A controller which allows for logging into an application
 *
 * @Flow\Scope("singleton")
 */
class TokenController extends AbstractAuthenticationController
{

    /**
     * @var array
     */
    protected $supportedMediaTypes = ['application/json'];

    /**
     * @var string
     */
    protected $defaultViewObjectName = JsonView::class;

    /**
     * @var array
     */
    protected $viewFormatToObjectNameMap = ['json' => 'Neos\Flow\Mvc\View\JsonView'];

    /**
     * @var Service
     * @Flow\Inject
     */
    protected $localizationService;

    /**
     * @var array
     * @Flow\InjectConfiguration(package="RFY.JWT", path="response.headers")
     */
    protected array $responseHeaders;

    /**
     *
     */
    public function initializeAuthenticateAction()
    {
        $this->response->setHttpHeader('Access-Control-Allow-Origin', $this->responseHeaders['Access-Control-Allow-Origin']);
        if ($this->request->getHttpRequest()->getMethod() === 'OPTIONS') {
            $this->response->setHttpHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
            $this->response->setStatusCode(204);
            return '';
        }
    }

    /**
     * Is called if authentication was successful.
     *
     * @param \Neos\Flow\Mvc\ActionRequest|NULL $originalRequest The request that was intercepted by the security framework, NULL if there was none
     * @return string
     */
    protected function onAuthenticationSuccess(ActionRequest $originalRequest = NULL)
    {
        $tokenFactory = new TokenFactory($this->request->getHttpRequest());
        $this->view->assign('value', ['token' => $tokenFactory->getJsonWebToken()]);
    }

    /**
     * Is called if authentication failed.
     *
     * @param AuthenticationRequiredException|null $exception The exception thrown while the authentication process
     * @return void
     */
    protected function onAuthenticationFailure(AuthenticationRequiredException $exception = null): void
    {
        if ($this->request->getHttpRequest()->getMethod() !== 'OPTIONS') {
            $this->response->setStatusCode(401);
        }
    }

    /**
     * Overwrite default behaviour
     */
    protected function errorAction()
    {
        return '';
    }
}
