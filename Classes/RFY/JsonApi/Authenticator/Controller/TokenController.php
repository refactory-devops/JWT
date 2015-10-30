<?php
namespace RFY\JsonApi\Authenticator\Controller;

/*                                                                        *
 * This script belongs to the TYPO3 Flow package "RFY.JsonApi.Authenticator".*
 *                                                                        *
 *                                                                        */

use RFY\JsonApi\Authenticator\JWT;
use TYPO3\Flow\Annotations as Flow;
use TYPO3\Flow\Http\Cookie;
use TYPO3\Flow\Security\Authentication\Controller\AbstractAuthenticationController;
use TYPO3\Flow\Security\Exception\AuthenticationRequiredException;
use TYPO3\Flow\Mvc\View\JsonView;
use TYPO3\Flow\Security\Cryptography\HashService;

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
		$payload = array('accountIdentifier' => 'indiener');
		$hmac = $this->hashService->generateHmac('token');

//		\TYPO3\Flow\var_dump(JWT::encode($payload, $hmac), 'test authenticate');

		parent::authenticateAction();

//		\TYPO3\Flow\var_dump('Done authenticate');
	}

	/**
	 * Is called if authentication was successful.
	 *
	 * @param \TYPO3\Flow\Mvc\ActionRequest $originalRequest The request that was intercepted by the security framework, NULL if there was none
	 * @return string
	 */
	public function onAuthenticationSuccess(\TYPO3\Flow\Mvc\ActionRequest $originalRequest = NULL) {
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
		// Respond with json formatted info
//		$this->addFlashMessage('The entered username or password was wrong', 'Wrong credentials', Message::SEVERITY_ERROR, array(), ($exception === null ? 1347016771 : $exception->getCode()));
		$this->view->assign('value', array('responseText' => 'Failure'));
	}

}