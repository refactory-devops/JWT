<?php
namespace RFY\JsonApi\Authenticator\Security\Authentication\Factory;

use RFY\JsonApi\Authenticator\Security\Authentication\Token\ApiToken;
use TYPO3\Flow\Annotations as Flow;

use TYPO3\Flow\Exception;
use TYPO3\Flow\Http\Request;
use TYPO3\Flow\Security\Cryptography\HashService;
use Firebase\JWT\JWT;
use TYPO3\Flow\Utility\Algorithms;

/**
 * Class TokenFactory
 *
 * @package RFY\JsonApi\Authenticator\Domain\Factory
 * @Flow\Scope("singleton")
 */
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
	 * @Flow\Inject
	 * @var \TYPO3\Flow\Security\AccountRepository
	 */
	protected $accountRepository;

	/**
	 * @Flow\Inject
	 * @var \TYPO3\Flow\Security\AccountFactory
	 */
	protected $accountFactory;

	/**
	 * @var array
	 * @Flow\InjectConfiguration(path="signature")
	 */
	protected $signature;

	/**
	 * @Flow\Inject
	 * @var \TYPO3\Flow\Persistence\PersistenceManagerInterface
	 */
	protected $persistenceManager;

	/**
	 * @var Request
	 */
	protected $request;

	/**
	 * @var ApiToken
	 */
	protected $apiToken;

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
		/** @var \TYPO3\Flow\Security\Account $account */
		$account = $this->securityContext->getAccount();

		$this->apiToken = $this->securityContext->getAuthenticationTokensOfType('RFY\JsonApi\Authenticator\Security\Authentication\Token\ApiToken')[0];

		if ($account->getAuthenticationProviderName() !== $this->apiToken->getAuthenticationProviderName()) {

			// TODO: Currently you can get only 1 tokenAccount because of the duplication restraint based on accountIdentifier & AuthenticationProviderName
			$account = $this->accountRepository->findActiveByAccountIdentifierAndAuthenticationProviderName($account->getAccountIdentifier(), $this->apiToken->getAuthenticationProviderName());

			if ($account === NULL) {
				$account = $this->generateTokenAccount();
			}
		}

		$payload = array();

		$payload['identifier'] = $this->persistenceManager->getIdentifierByObject($account);
		$payload['accountIdentifier'] = $account->getAccountIdentifier();
		$payload['user_agent'] = $this->request->getHeader('HTTP_USER_AGENT');
		$payload['ip_address'] = $this->request->getClientIpAddress();

		if ($account->getCreationDate() instanceof \DateTime) {
			$payload['creationDate'] = $account->getCreationDate()->getTimestamp();
		}

		if ($account->getExpirationDate() instanceof \DateTime) {
			$payload['expirationDate'] = $account->getExpirationDate()->getTimestamp();
		}

		// Add hmac
		$hmac = $this->hashService->generateHmac($this->signature);
		return JWT::encode($payload, $hmac);
	}

	/**
	 * @return \TYPO3\Flow\Security\Account
	 * @throws Exception
	 * @throws \TYPO3\Flow\Persistence\Exception\IllegalObjectTypeException
	 */
	protected function generateTokenAccount() {
		$account = $this->securityContext->getAccount();

		$tokenAccount = $this->accountFactory->createAccountWithPassword($account->getAccountIdentifier(), Algorithms::generateRandomString(25), array_keys($account->getRoles()), $this->apiToken->getAuthenticationProviderName());
		$this->accountRepository->add($tokenAccount);
		$this->persistenceManager->persistAll();

		return $tokenAccount;
	}
}