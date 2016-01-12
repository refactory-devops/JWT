<?php
namespace RFY\JWT\Security\Authentication\Provider;

use TYPO3\Flow\Annotations as Flow;
use TYPO3\Flow\Security\Account;
use TYPO3\Flow\Security\Authentication\Provider\AbstractProvider;
use TYPO3\Flow\Security\Authentication\TokenInterface;
use TYPO3\Flow\Security\Cryptography\HashService;
use TYPO3\Flow\Security\Exception\UnsupportedAuthenticationTokenException;

use RFY\JWT\Security\Authentication\Token\JwtToken;
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
	 * @var array
	 * @Flow\InjectConfiguration(path="signature")
	 */
	protected $signature;

	/**
	 * Returns the class names of the tokens this provider can authenticate.
	 *
	 * @return array
	 */
	public function getTokenClassNames() {
		return array('RFY\JWT\Security\Authentication\Token\JwtToken');
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
		if (!($authenticationToken instanceof JwtToken)) {
			throw new UnsupportedAuthenticationTokenException('This provider cannot authenticate the given token.', 1417040168);
		}

		/** @var $account Account */
		$account = NULL;
		$credentials = $authenticationToken->getCredentials();

		if (!is_array($credentials) || !isset($credentials['token'])) {
			$authenticationToken->setAuthenticationStatus(TokenInterface::NO_CREDENTIALS_GIVEN);
			return;
		}

		$hmac = $this->hashService->generateHmac($this->signature);

		$payload = NULL;
		try {
			$payload = (array)JWT::decode($credentials['token'], $hmac, array('HS256'));
		} catch (\Exception $exception) {
			$authenticationToken->setAuthenticationStatus(TokenInterface::WRONG_CREDENTIALS);
		}

		if (isset($credentials['username'])) {
			$providerName = $this->name;
			$accountRepository = $this->accountRepository;
			$this->securityContext->withoutAuthorizationChecks(function() use ($credentials, $providerName, $accountRepository, &$account) {
				$account = $accountRepository->findActiveByAccountIdentifierAndAuthenticationProviderName($credentials['username'], $providerName);
			});

			if ($this->hashService->validatePassword($credentials['password'], $account->getCredentialsSource())) {
				$authenticationToken->setAuthenticationStatus(TokenInterface::AUTHENTICATION_SUCCESSFUL);
				$authenticationToken->setAccount($account);
				return;
			} else {
				$authenticationToken->setAuthenticationStatus(TokenInterface::WRONG_CREDENTIALS);
				return;
			}
		}

		if ($credentials['user_agent'] === $payload['user_agent'] && $credentials['ip_address'] === $payload['ip_address']) {
			$this->securityContext->withoutAuthorizationChecks(function() use ($payload, &$account) {
				$account = $this->accountRepository->findActiveByAccountIdentifierAndAuthenticationProviderName($payload['identifier'], $this->name);
			});
		}

		if (is_object($account) && $this->verifyDates($account, $payload)) {
			$authenticationToken->setAuthenticationStatus(TokenInterface::AUTHENTICATION_SUCCESSFUL);
			$authenticationToken->setAccount($account);
			return;
		}

		$authenticationToken->setAuthenticationStatus(TokenInterface::WRONG_CREDENTIALS);
		return;
	}

	/**
	 * @param Account $account
	 * @param array $payload
	 * @return bool
	 */
	protected function verifyDates($account, $payload) {
		if ($account->getCreationDate() instanceof \DateTime) {
			if ($payload['creationDate'] !== $account->getCreationDate()->getTimestamp()) {
				return false;
			}
		}

		if ($account->getExpirationDate() instanceof \DateTime) {
			if ($payload['expirationDate'] !== $account->getExpirationDate()->getTimestamp()) {
				return false;
			}
		}

		return true;
	}
}