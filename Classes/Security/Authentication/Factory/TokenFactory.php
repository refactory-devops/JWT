<?php

namespace RFY\JWT\Security\Authentication\Factory;

use RFY\JWT\Security\Authentication\Token\JwtToken;
use Neos\Flow\Annotations as Flow;
use Neos\Flow\Exception;
use Neos\Flow\Http\Request;
use Neos\Flow\Security\Cryptography\HashService;
use Neos\Flow\Utility\Algorithms;
use Firebase\JWT\JWT;

/**
 * Class TokenFactory
 *
 * @package RFY\JWT\Domain\Factory
 * @Flow\Scope("singleton")
 */
class TokenFactory
{

    /**
     * @Flow\Inject
     * @var HashService
     */
    protected $hashService;

    /**
     * @var \Neos\Flow\Security\Context
     * @Flow\Inject
     */
    protected $securityContext;

    /**
     * @Flow\Inject
     * @var \Neos\Flow\Security\AccountRepository
     */
    protected $accountRepository;

    /**
     * @Flow\Inject
     * @var \Neos\Flow\Security\AccountFactory
     */
    protected $accountFactory;

    /**
     * @Flow\Inject
     * @var \Neos\Party\Domain\Repository\PartyRepository
     */
    protected $partyRepository;

    /**
     * @var string
     * @Flow\InjectConfiguration(path="signature")
     */
    protected $signature;

    /**
     * @Flow\Inject
     * @var \Neos\Flow\Persistence\PersistenceManagerInterface
     */
    protected $persistenceManager;

    /**
     * @var Request
     */
    protected $request;

    /**
     * @var JwtToken
     */
    protected $jwtToken;

    /**
     * @param $request
     */
    public function __construct($request)
    {
        $this->request = $request;
    }

    /**
     * @return string
     * @throws Exception
     * @throws \Neos\Flow\Persistence\Exception\IllegalObjectTypeException
     * @throws \Neos\Flow\Security\Exception\InvalidArgumentForHashGenerationException
     */
    public function getJWTToken()
    {
        /** @var \Neos\Flow\Security\Account $account */
        $account = $this->securityContext->getAccount();

        $this->jwtToken = $this->securityContext->getAuthenticationTokensOfType('RFY\JWT\Security\Authentication\Token\JwtToken')[0];

        if ($account->getAuthenticationProviderName() !== $this->jwtToken->getAuthenticationProviderName()) {

            // TODO: Currently you can get only 1 tokenAccount because of the duplication restraint based on accountIdentifier & AuthenticationProviderName
            $account = $this->accountRepository->findActiveByAccountIdentifierAndAuthenticationProviderName($account->getAccountIdentifier(), $this->jwtToken->getAuthenticationProviderName());

            if ($account === NULL) {
                $account = $this->generateTokenAccount();
            }
        }

        $payload = array();

        $payload['identifier'] = $account->getAccountIdentifier();
        $payload['partyIdentifier'] = $this->persistenceManager->getIdentifierByObject($this->partyRepository->findOneHavingAccount($account));
        $payload['user_agent'] = $this->request->getHeader('User-Agent');
        $payload['ip_address'] = $this->request->getAttribute(Request::ATTRIBUTE_CLIENT_IP);

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
     * @return \Neos\Flow\Security\Account
     * @throws Exception
     * @throws \Neos\Flow\Persistence\Exception\IllegalObjectTypeException
     */
    protected function generateTokenAccount()
    {
        $account = $this->securityContext->getAccount();

        $tokenAccount = $this->accountFactory->createAccountWithPassword($account->getAccountIdentifier(), Algorithms::generateRandomString(25), array_keys($account->getRoles()), $this->apiToken->getAuthenticationProviderName());
        $this->accountRepository->add($tokenAccount);
        $this->persistenceManager->persistAll();

        return $tokenAccount;
    }
}