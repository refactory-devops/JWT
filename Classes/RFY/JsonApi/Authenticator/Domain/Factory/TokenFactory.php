<?php
namespace RFY\JsonApi\Authenticator\Domain\Factory;

use TYPO3\Flow\Annotations as Flow;

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
	 * @var string
	 */
	protected $jwtToken = '';

	public function __construct($request) {

	}

	public function getJWTToken() {
		/** @var \TYPO3\Flow\Security\Account $account */
		$account = $this->securityContext->getAccount();
		$payload = array('accountIdentifier' => $account->getAccountIdentifier());

		$hmac = $this->hashService->generateHmac('token');

		return JWT::encode($payload, $hmac);
	}

}