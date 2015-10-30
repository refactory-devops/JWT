<?php
namespace RFY\JsonApi\Authenticator\Security\Authentication\Provider;

use TYPO3\Flow\Annotations as Flow;
use TYPO3\Flow\Security\Account;
use TYPO3\Flow\Security\Authentication\Provider\PersistedUsernamePasswordProvider;
use TYPO3\Flow\Security\Authentication\TokenInterface;
use TYPO3\Flow\Security\Cryptography\HashService;
use TYPO3\Flow\Security\Exception\UnsupportedAuthenticationTokenException;

use RFY\JsonApi\Authenticator\Security\Authentication\Token\ApiToken;
use TYPO3\Flow\Security\Authentication\Token\UsernamePassword;
use RFY\JsonApi\Authenticator\JWT;

/**
 * An authentication provider that authenticates ApiTokens
 */
class PersistedApiTokenProvider extends PersistedUsernamePasswordProvider {

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
		return array('RFY\JsonApi\Authenticator\Security\Authentication\Token\ApiToken', 'TYPO3\Flow\Security\Authentication\Token\UsernamePassword');
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
		if (!($authenticationToken instanceof ApiToken) && !($authenticationToken instanceof UsernamePassword)) {
			throw new UnsupportedAuthenticationTokenException('This provider cannot authenticate the given token.', 1417040168);
		}


		/** @var $account Account */
		$account = NULL;
		$credentials = $authenticationToken->getCredentials();

			// Authenticate by username and password
		if (is_array($credentials) && isset($credentials['username'])) {
			$providerName = $this->name;
			$accountRepository = $this->accountRepository;
			$this->securityContext->withoutAuthorizationChecks(function() use ($credentials, $providerName, $accountRepository, &$account) {
				$account = $accountRepository->findActiveByAccountIdentifierAndAuthenticationProviderName($credentials['username'], $providerName);
			});

			if (is_object($account)) {
				if ($this->hashService->validatePassword($credentials['password'], $account->getCredentialsSource())) {
					$authenticationToken->setAuthenticationStatus(TokenInterface::AUTHENTICATION_SUCCESSFUL);
					$authenticationToken->setAccount($account);
				} else {
					$authenticationToken->setAuthenticationStatus(TokenInterface::WRONG_CREDENTIALS);
				}
			} elseif ($authenticationToken->getAuthenticationStatus() !== TokenInterface::AUTHENTICATION_SUCCESSFUL) {
				$authenticationToken->setAuthenticationStatus(TokenInterface::NO_CREDENTIALS_GIVEN);
			}

			return;
		} elseif (!is_array($credentials) || !isset($credentials['token'])) {
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

		// TODO check further JWT properties (e.g. expiration date, client IP, ...)
		$this->securityContext->withoutAuthorizationChecks(function() use ($payload, &$account) {
			$account = $this->accountRepository->findActiveByAccountIdentifierAndAuthenticationProviderName($payload['accountIdentifier'], $this->name);
		});

		if ($account === NULL) {
			$authenticationToken->setAuthenticationStatus(TokenInterface::WRONG_CREDENTIALS);
			return;
		}

		$authenticationToken->setAuthenticationStatus(TokenInterface::AUTHENTICATION_SUCCESSFUL);
		$authenticationToken->setAccount($account);
	}
}