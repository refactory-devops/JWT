<?php

namespace RFY\JWT\Security\Authentication\Provider;

use Neos\Flow\Annotations as Flow;
use Neos\Flow\Security\Account;
use Neos\Flow\Security\Authentication\Provider\AbstractProvider;
use Neos\Flow\Security\Authentication\TokenInterface;
use Neos\Flow\Security\Cryptography\HashService;
use Neos\Flow\Security\Exception\UnsupportedAuthenticationTokenException;
use Neos\Flow\Security\Policy\PolicyService;
use RFY\JWT\Security\Authentication\Token\JsonWebToken;
use RFY\JWT\Security\JwtAccount;

/**
 * An authentication provider that authenticates ApiTokens
 */
class JsonWebAuthenticationProvider extends AbstractProvider
{

    /**
     * @Flow\Inject
     * @var HashService
     */
    protected $hashService;

    /**
     * @var \Neos\Flow\Security\AccountRepository
     * @Flow\Inject
     */
    protected $accountRepository;

    /**
     * @Flow\Inject
     * @var \Neos\Party\Domain\Repository\PartyRepository
     */
    protected $partyRepository;

    /**
     * @var \Neos\Flow\Security\Context
     * @Flow\Inject
     */
    protected $securityContext;

    /**
     * @var \Neos\Flow\Persistence\PersistenceManagerInterface
     * @Flow\Inject
     */
    protected $persistenceManager;

    /**
     * @var array
     * @Flow\InjectConfiguration(path="claimMapping")
     */
    protected $claimMapping;

    /**
     * @var PolicyService
     * @Flow\Inject
     */
    protected $policyService;

    /**
     * Returns the class names of the tokens this provider can authenticate.
     *
     * @return array
     */
    public function getTokenClassNames(): array
    {
        return [JsonWebToken::class];
    }

    /**
     * Returns true if the given token can be authenticated by this provider
     *
     * @param TokenInterface $token The token that should be authenticated
     * @return boolean true if the given token class can be authenticated by this provider
     */
    public function canAuthenticate(TokenInterface $token): bool
    {
        return ($token instanceof JsonWebToken);
    }

    /**
     * Checks the given token for validity and sets the token authentication status
     * accordingly (success, wrong credentials or no credentials given).
     *
     * @param TokenInterface $authenticationToken The token to be authenticated
     * @throws UnsupportedAuthenticationTokenException
     * @throws \Neos\Flow\Persistence\Exception\IllegalObjectTypeException
     * @throws \Neos\Flow\Security\Exception\InvalidAuthenticationStatusException
     */
    public function authenticate(TokenInterface $authenticationToken)
    {
        if (!($authenticationToken instanceof JsonWebToken)) {
            throw new UnsupportedAuthenticationTokenException('This provider cannot authenticate the given token.', 1417040168);
        }

        /** @var $account Account */
        $account = null;
        $credentials = $authenticationToken->getCredentials();

        // Fresh Authentication of Username and Password
        if (isset($credentials['username'])) {
            $providerName = $this->name;
            $accountRepository = $this->accountRepository;
            $this->securityContext->withoutAuthorizationChecks(function () use ($credentials, $providerName, $accountRepository, &$account) {
                $account = $accountRepository->findActiveByAccountIdentifierAndAuthenticationProviderName($credentials['username'], $providerName);
            });

            $authenticationToken->setAuthenticationStatus(TokenInterface::WRONG_CREDENTIALS);
            if ($account === null) {
                // validate the account anyways (with a dummy salt) in order to prevent timing attacks on this provider
                $this->hashService->validatePassword($credentials['password'], 'bcrypt=>$2a$16$RW.NZM/uP3mC8rsXKJGuN.2pG52thRp5w39NFO.ShmYWV7mJQp0rC');
                return;
            }

            if ($this->hashService->validatePassword($credentials['password'], $account->getCredentialsSource())) {
                $account->authenticationAttempted(TokenInterface::AUTHENTICATION_SUCCESSFUL);
                $authenticationToken->setAuthenticationStatus(TokenInterface::AUTHENTICATION_SUCCESSFUL);
                $this->accountRepository->update($account);
                $this->persistenceManager->whitelistObject($account);
            } else {
                $authenticationToken->setAuthenticationStatus(TokenInterface::WRONG_CREDENTIALS);
                return;
            }
        }

        if (\is_object($account)) {
            $jwtAccount = new JwtAccount();
            $jwtAccount->setAccountIdentifier($account->getAccountIdentifier());
            $jwtAccount->setAuthenticationProviderName('JwtAuthenticationProvider');

            $rolesClaim = $this->claimMapping['roles'];
            foreach ($rolesClaim as $key => $roleClaim) {
                $flowRoleName = $this->claimMapping['roles'][$key];
                $role = $this->policyService->getRole($flowRoleName);
                $account->addRole($role);
            }

            $party = $this->partyRepository->findOneHavingAccount($account);
            $jwtAccount->setParty($party);

            $authenticationToken->setAuthenticationStatus(TokenInterface::AUTHENTICATION_SUCCESSFUL);
            $authenticationToken->setAccount($jwtAccount);

            return;
        }

        $authenticationToken->setAuthenticationStatus(TokenInterface::WRONG_CREDENTIALS);
    }
}
