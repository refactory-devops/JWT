<?php
namespace RFY\JsonApi\Authenticator\Security\Authentication\Token;

use TYPO3\Flow\Annotations as Flow;
use TYPO3\Flow\Mvc\ActionRequest;
use TYPO3\Flow\Security\Authentication\Token\AbstractToken;
use TYPO3\Flow\Security\Authentication\Token\SessionlessTokenInterface;

/**
 * An authentication token used for simple username and password authentication.
 */
class ApiToken extends AbstractToken implements SessionlessTokenInterface {

	/**
	 * The jwt credentials
	 *
	 * @var array
	 * @Flow\Transient
	 */
	protected $credentials = array('token' => '');

	/**
	 * @param ActionRequest $actionRequest The current action request
	 * @return void
	 */
	public function updateCredentials(ActionRequest $actionRequest) {
		$apiTokenCookie = $actionRequest->getHttpRequest()->getCookie('token');

		if ($actionRequest->getHttpRequest()->getMethod() === 'OPTIONS') {
			return;
		}

		$authorizationHeader = $actionRequest->getHttpRequest()->getHeaders()->get('Authorization');

		if (substr($authorizationHeader, 0, 5) === 'Token') {
			$this->credentials['token'] = substr($authorizationHeader, 6);
			$this->credentials['user_agent'] = $actionRequest->getHttpRequest()->getHeader('HTTP_USER_AGENT');
			$this->setAuthenticationStatus(self::AUTHENTICATION_NEEDED);
		} elseif ($apiTokenCookie !== NULL) {
			$this->credentials['token'] = $apiTokenCookie;
			$this->credentials['user_agent'] = $actionRequest->getHttpRequest()->getHeader('HTTP_USER_AGENT');
			$this->setAuthenticationStatus(self::AUTHENTICATION_NEEDED);
		} else {
			$this->credentials = array('token'=> NULL);
			$this->authenticationStatus = self::NO_CREDENTIALS_GIVEN;
			return;
		}
	}

	/**
	 * Returns a string representation of the token for logging purposes.
	 *
	 * @return string The username credential
	 */
	public function  __toString() {
		return 'TOKEN: "' . substr($this->credentials['token'], 0, 10) . '..."';
	}
}