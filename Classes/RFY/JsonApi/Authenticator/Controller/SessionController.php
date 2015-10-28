<?php
namespace RFY\JsonApi\Authenticator\Controller;

/*                                                                        *
 * This script belongs to the TYPO3 Flow package "RFY.JsonApi.Authenticator".*
 *                                                                        *
 *                                                                        */

use TYPO3\Flow\Annotations as Flow;
use TYPO3\Flow\Security\Authentication\Controller\AbstractAuthenticationController;

/**
 * A controller which allows for logging into an application
 *
 * @Flow\Scope("singleton")
 */
class SessionController extends AbstractAuthenticationController {

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
	 * Authenticates an account by invoking the Provider based Authentication Manager.
	 *
	 * On successful authentication redirects to the list of posts, otherwise returns
	 * to the login screen.
	 *
	 * @return void
	 * @throws \TYPO3\Flow\Security\Exception\AuthenticationRequiredException
	 */
	public function authenticateAction() {
		$authenticationException = NULL;
		try {
			$this->authenticationManager->authenticate();
		} catch (\TYPO3\Flow\Security\Exception\AuthenticationRequiredException $exception) {
			$authenticationException = $exception;

//			$response = new Response();
//			$response->setType('error');
//			$response->setMessage('The entered username or password was wrong!');
//			$this->view->assign('value', $response);
		}

		if ($this->authenticationManager->isAuthenticated()) {
			$storedRequest = $this->securityContext->getInterceptedRequest();
			if ($storedRequest !== NULL) {
				$this->securityContext->setInterceptedRequest(NULL);
			}
			$this->onAuthenticationSuccess($storedRequest);
		} else {
			$this->onAuthenticationFailure($authenticationException);
		}

		$this->response->setHeader('Access-Control-Allow-Origin', '*');
	}

	/**
	 * Is called if authentication was successful.
	 *
	 * @param \TYPO3\Flow\Mvc\ActionRequest $originalRequest The request that was intercepted by the security framework, NULL if there was none
	 * @return string
	 */
	public function onAuthenticationSuccess(\TYPO3\Flow\Mvc\ActionRequest $originalRequest = NULL) {
		// Respond with authenticated account?
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
	}

}