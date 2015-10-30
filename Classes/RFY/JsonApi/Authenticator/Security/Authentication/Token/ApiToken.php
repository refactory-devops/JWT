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
		$ApiTokenCookie = $actionRequest->getHttpRequest()->getCookie('token');

		if ($ApiTokenCookie === NULL) {
			return;
		}

		$this->credentials['token'] = $ApiTokenCookie->getValue();
		$this->setAuthenticationStatus(self::AUTHENTICATION_NEEDED);
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