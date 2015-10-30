<?php
namespace RFY\JsonApi\Authenticator\Controller;

/*                                                                        *
 * This script belongs to the TYPO3 Flow package "RFY.JsonApi.Authenticator".*
 *                                                                        *
 *                                                                        */

use TYPO3\Flow\Annotations as Flow;
use TYPO3\Flow\Http\Cookie;
use TYPO3\Flow\Security\Authentication\Controller\AbstractAuthenticationController;
use TYPO3\Flow\Security\Authentication\TokenInterface;
use TYPO3\Flow\Security\Exception\AuthenticationRequiredException;
use TYPO3\Flow\Mvc\View\JsonView;
use TYPO3\Flow\Security\Cryptography\HashService;
use RFY\JsonApi\Authenticator\JWT;

/**
 * A controller which allows for logging into an application
 *
 * @Flow\Scope("singleton")
 */
class TokenController extends AbstractAuthenticationController {

	/**
	 * @Flow\Inject
	 * @var HashService
	 */
	protected $hashService;

	/**
	 * @var array
	 */
	protected $supportedMediaTypes = array('application/json');

	/**
	 * @var array
	 */
	protected $viewFormatToObjectNameMap = array(
		'json' => 'TYPO3\Flow\Mvc\View\JsonView'
	);

	/**
	 * @var \TYPO3\Flow\I18n\Translator
	 * @Flow\Inject
	 */
	protected $translator;

	/**
	 * @var \TYPO3\Flow\I18n\Service
	 * @Flow\Inject
	 */
	protected $localizationService;

	/**
	 *
	 */
	public function initializeAuthenticateAction() {
		$this->response->setHeader('Access-Control-Allow-Headers', 'Authorization');
		$this->response->setHeader('Access-Control-Allow-Origin', '*');

		if ($this->request->getHttpRequest()->getMethod() === 'OPTIONS') {
			$this->response->setStatus(204);

			return '';
		}
	}

	/**
	 * Authenticates an account by invoking the Provider based Authentication Manager.
	 *
	 * On successful authentication redirects to the list of posts, otherwise returns
	 * to the login screen.
	 *
	 * @return void
	 * @throws \TYPO3\Flow\Security\Exception\AuthenticationRequiredException
	 */
	public function authenticateAction() {
		parent::authenticateAction();
	}

	/**
	 * Is called if authentication was successful.
	 *
	 * @param \TYPO3\Flow\Mvc\ActionRequest $originalRequest The request that was intercepted by the security framework, NULL if there was none
	 * @return string
	 */
	protected function onAuthenticationSuccess(\TYPO3\Flow\Mvc\ActionRequest $originalRequest = NULL) {
		/** @var \TYPO3\Flow\Security\Account $account */
		$account = $this->securityContext->getAccount();
		$payload = array('accountIdentifier' => $account->getAccountIdentifier());

		$hmac = $this->hashService->generateHmac('token');

		$tokenCookie = new Cookie('token', JWT::encode($payload, $hmac));

		$this->response->setCookie($tokenCookie);

		$this->view->assign('value', array('token' => JWT::encode($payload, $hmac)));
	}

	/**
	 * Is called if authentication failed.
	 *
	 * @param AuthenticationRequiredException $exception The exception thrown while the authentication process
	 * @return void
	 */
	protected function onAuthenticationFailure(AuthenticationRequiredException $exception = null) {

		/** @var TokenInterface $token */
		foreach($this->authenticationManager->getTokens() as $token) {
			$responseIdentifier = $token->getAuthenticationStatus();
		}

		$locale = $this->localizationService->getConfiguration()->getCurrentLocale();
		$package = $this->controllerContext->getRequest()->getControllerPackageKey();


		$this->view->assign('value', array(
			'responseText' => $this->translator->translateById('authentication.response.' . $responseIdentifier, array(), NULL, $locale, 'Main', $package),
			'responseIdentifier' => $responseIdentifier
		));
	}

}