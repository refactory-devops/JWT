<?php
namespace RFY\JsonApi\Authenticator\Domain\Factory;

use TYPO3\Flow\Annotations as Flow;

use TYPO3\Flow\Http\Request;
use TYPO3\Flow\Security\Cryptography\HashService;
use Firebase\JWT\JWT;

class TokenFactory {

	/**
	 * @Flow\Inject
	 * @var HashService
	 */
	protected $hashService;

	/**
	 * @var \TYPO3\Flow\Security\Context
	 * @Flow\Inject
	 */
	protected $securityContext;

	/**
	 * @var Request
	 */
	protected $request;

	/**
	 * @var string
	 */
	protected $jwtToken = '';

	/**
	 * @param $request
	 */
	public function __construct($request) {
		$this->request = $request;
	}

	/**
	 * @return string
	 * @throws \TYPO3\Flow\Security\Exception\InvalidArgumentForHashGenerationException
	 */
	public function getJWTToken() {
		$payload = array();

		/** @var \TYPO3\Flow\Security\Account $account */
		$account = $this->securityContext->getAccount();

		$payload['accountIdentifier'] = $account->getAccountIdentifier();
		$payload['authenticationProviderName'] = $account->getAuthenticationProviderName();
		$payload['user_agent'] = $this->request->getHeader('HTTP_USER_AGENT');
		$payload['ip_address'] = $this->request->getClientIpAddress();
		$payload['creationDate'] = time();

			// Add hmac
		$hmac = $this->hashService->generateHmac('JWTtoken');

		return JWT::encode($payload, $hmac);
	}

}