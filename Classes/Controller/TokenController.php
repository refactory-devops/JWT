<?php

namespace RFY\JWT\Controller;

/*                                                                        *
 * This script belongs to the Neos Flow package "RFY.JsonApi.Authenticator".*
 *                                                                        *
 *                                                                        */

use Neos\Flow\Annotations as Flow;

use Neos\Flow\Security\Authentication\Controller\AbstractAuthenticationController;
use Neos\Flow\Security\Authentication\TokenInterface;
use Neos\Flow\Security\Exception\AuthenticationRequiredException;
use RFY\JWT\Security\Authentication\Factory\TokenFactory;

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
    protected $supportedMediaTypes = array('application/json');

    /**
     * @var array
     */
    protected $viewFormatToObjectNameMap = array(
        'json' => 'Neos\Flow\Mvc\View\JsonView'
    );

    /**
     * @var \Neos\Flow\I18n\Translator
     * @Flow\Inject
     */
    protected $translator;

    /**
     * @var \Neos\Flow\I18n\Service
     * @Flow\Inject
     */
    protected $localizationService;

    /**
     * @var array
     * @Flow\InjectConfiguration(package="RFY.JWT", path="response.headers")
     */
    protected $responseHeaders;

    /**
     *
     */
    public function initializeAuthenticateAction()
    {
        $this->response = $this->response->withHeader('Access-Control-Allow-Origin', $this->responseHeaders['Access-Control-Allow-Origin']);

        if ($this->request->getHttpRequest()->getMethod() === 'OPTIONS') {
            $this->response = $this->response->withHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
            $this->response = $this->response->withStatus(204);
            return '';
        }
    }

    /**
     * Is called if authentication was successful.
     *
     * @param \Neos\Flow\Mvc\ActionRequest|NULL $originalRequest The request that was intercepted by the security framework, NULL if there was none
     * @return string|void
     */
    protected function onAuthenticationSuccess(\Neos\Flow\Mvc\ActionRequest $originalRequest = NULL)
    {
        $tokenFactory = new TokenFactory($this->request->getHttpRequest());

        $this->view->assign('value', ['token' => $tokenFactory->getJsonWebToken()]);
    }

    /**
     * Is called if authentication failed.
     *
     * @param AuthenticationRequiredException $exception The exception thrown while the authentication process
     * @return void
     */
    protected function onAuthenticationFailure(AuthenticationRequiredException $exception = null)
    {
        $responseIdentifier = 0;

        /** @var TokenInterface $token */
        foreach ($this->authenticationManager->getTokens() as $token) {
            if ($token->getAuthenticationStatus() > $responseIdentifier) {
                $responseIdentifier = $token->getAuthenticationStatus();
            }
        }

        $locale = $this->localizationService->getConfiguration()->getCurrentLocale();
        $package = $this->controllerContext->getRequest()->getControllerPackageKey();

        $this->view->assign('value', [
                'responseText' => $this->translator->translateById('authentication.response.' . $responseIdentifier, [], null, $locale, 'Main', $package),
                'responseIdentifier' => $responseIdentifier
            ]
        );

        if ($this->request->getHttpRequest()->getMethod() !== 'OPTIONS') {
            $this->response = $this->response->withStatus(401);
        }
    }

    /**
     * Overwrite default behaviour
     */
    protected function errorAction()
    {
    }
}
