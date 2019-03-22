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
     *
     */
    public function initializeAuthenticateAction()
    {
        $this->response->setHeader('Access-Control-Allow-Origin', '*');

        if ($this->request->getHttpRequest()->getMethod() === 'OPTIONS') {
            $this->response->setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
            $this->response->withStatus(204);
            return '';
        }
    }

    /**
     * Is called if authentication was successful.
     *
     * @param \Neos\Flow\Mvc\ActionRequest|NULL $originalRequest The request that was intercepted by the security framework, NULL if there was none
     * @return string|void
     * @throws \Neos\Flow\Exception
     * @throws \Neos\Flow\Persistence\Exception\IllegalObjectTypeException
     * @throws \Neos\Flow\Security\Exception\InvalidArgumentForHashGenerationException
     */
    protected function onAuthenticationSuccess(\Neos\Flow\Mvc\ActionRequest $originalRequest = NULL)
    {
        $tokenFactory = new TokenFactory($this->request->getHttpRequest());

        $this->view->assign('value', array('token' => $tokenFactory->getJWTToken()));
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

        $this->view->assign('value', array(
            'responseText' => $this->translator->translateById('authentication.response.' . $responseIdentifier, array(), NULL, $locale, 'Main', $package),
            'responseIdentifier' => $responseIdentifier
        ));

        if ($this->request->getHttpRequest()->getMethod() !== 'OPTIONS') {
            $this->response->setStatus(401);
        }
    }

    /**
     * Overwrite default behaviour
     */
    protected function errorAction()
    {
    }
}