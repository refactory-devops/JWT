<?php
namespace RFY\JsonApi\Authenticator\Security\Authentication\Provider;

use TYPO3\Flow\Annotations as Flow;
use TYPO3\Flow\Security\Account;
use TYPO3\Flow\Security\Authentication\Provider\AbstractProvider;
use TYPO3\Flow\Security\Authentication\TokenInterface;
use TYPO3\Flow\Security\Cryptography\HashService;
use TYPO3\Flow\Security\Exception\UnsupportedAuthenticationTokenException;

use RFY\JsonApi\Authenticator\Security\Authentication\Token\ApiToken;
use Firebase\JWT\JWT;

/**
 * An authentication provider that authenticates ApiTokens
 */
class PersistedApiTokenProvider extends AbstractProvider {

	/**
	 * @Flow\Inject
	 * @var HashService
	 */
	protected $hashService;

	/**
	 * @var \TYPO3\Flow\Security\AccountRepository
	 * @Flow\Inject
	 */
	protected $accountRepository;

	/**
	 * @var \TYPO3\Flow\Security\Context
	 * @Flow\Inject
	 */
	protected $securityContext;

	/**
	 * Returns the class names of the tokens this provider can authenticate.
	 *
	 * @return array
	 */
	public function getTokenClassNames() {
		return array('RFY\JsonApi\Authenticator\Security\Authentication\Token\ApiToken');
	}

	/**
	 * Checks the given token for validity and sets the token authentication status
	 * accordingly (success, wrong credentials or no credentials given).
	 *
	 * @param TokenInterface $authenticationToken The token to be authenticated
	 * @return void
	 * @throws UnsupportedAuthenticationTokenException
	 */
	public function authenticate(TokenInterface $authenticationToken) {
		if (!($authenticationToken instanceof ApiToken)) {
			throw new UnsupportedAuthenticationTokenException('This provider cannot authenticate the given token.', 1417040168);
		}

		/** @var $account Account */
		$account = NULL;
		$credentials = $authenticationToken->getCredentials();

		if (!is_array($credentials) || !isset($credentials['token'])) {
			$authenticationToken->setAuthenticationStatus(TokenInterface::NO_CREDENTIALS_GIVEN);
			return;
		}

		$hmac = $this->hashService->generateHmac('token');

		$payload = NULL;

		try {
			$payload = (array)JWT::decode($credentials['token'], $hmac);
		} catch (\Exception $exception) {
			$authenticationToken->setAuthenticationStatus(TokenInterface::WRONG_CREDENTIALS);
		}
		if ($payload === NULL || !isset($payload['accountIdentifier'])) {
			$authenticationToken->setAuthenticationStatus(TokenInterface::WRONG_CREDENTIALS);
			return;
		}

		if ($credentials['user_agent'] === $payload['user_agent'] && $credentials['ip_address'] === $payload['ip_address']) {
			$this->securityContext->withoutAuthorizationChecks(function() use ($payload, &$account) {
				$account = $this->accountRepository->findActiveByAccountIdentifierAndAuthenticationProviderName($payload['accountIdentifier'], $this->name);
			});
		}

		if ($account === NULL) {
			$authenticationToken->setAuthenticationStatus(TokenInterface::WRONG_CREDENTIALS);
			return;
		}

		$authenticationToken->setAuthenticationStatus(TokenInterface::AUTHENTICATION_SUCCESSFUL);
		$authenticationToken->setAccount($account);
	}
}