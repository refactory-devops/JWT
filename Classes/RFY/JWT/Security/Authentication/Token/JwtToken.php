<?php
namespace RFY\JWT\Security\Authentication\Token;

use TYPO3\Flow\Annotations as Flow;
use TYPO3\Flow\Mvc\ActionRequest;
use TYPO3\Flow\Security\Authentication\Token\AbstractToken;
use TYPO3\Flow\Security\Authentication\Token\SessionlessTokenInterface;

/**
 * An authentication token used for simple username and password authentication.
 */
class JwtToken extends AbstractToken implements SessionlessTokenInterface {

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
		if ($actionRequest->getHttpRequest()->getMethod() === 'OPTIONS') {
			return;
		}

		$authorizationHeader = $actionRequest->getHttpRequest()->getHeaders()->get('Authorization');
		$authorizationArguments = $actionRequest->getArguments();

		if (isset($authorizationArguments['username']) && isset($authorizationArguments['password'])) {
			$this->credentials['username'] = $authorizationArguments['username'];
			$this->credentials['password'] = $authorizationArguments['password'];
			$this->setAuthenticationStatus(self::AUTHENTICATION_NEEDED);
			return;
		} elseif (substr($authorizationHeader, 0, 6) === 'Bearer') {
			$this->credentials['token'] = substr($authorizationHeader, 7);
			$this->credentials['user_agent'] = $actionRequest->getHttpRequest()->getHeader('User-Agent');
			$this->credentials['ip_address'] = $actionRequest->getHttpRequest()->getClientIpAddress();
			$this->setAuthenticationStatus(self::AUTHENTICATION_NEEDED);
			return;
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
		return 'TOKEN: "' . substr($this->credentials['token'], 0, 30) . '..."';
	}
}