<?php

namespace RFY\JWT\Security\Authentication\Provider;

use Neos\Flow\Annotations as Flow;
use Neos\Flow\Security\Account;
use Neos\Flow\Security\Authentication\Provider\AbstractProvider;
use Neos\Flow\Security\Authentication\TokenInterface;
use Neos\Flow\Security\Cryptography\HashService;
use Neos\Flow\Security\Exception\UnsupportedAuthenticationTokenException;
use RFY\JWT\Security\Authentication\Token\JwtToken;
use Firebase\JWT\JWT;

/**
 * An authentication provider that authenticates ApiTokens
 */
class PersistedApiTokenProvider extends AbstractProvider
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
     * @var string
     * @Flow\InjectConfiguration(path="signature")
     */
    protected $signature;

    /**
     * Returns the class names of the tokens this provider can authenticate.
     *
     * @return array
     */
    public function getTokenClassNames()
    {
        return array('RFY\JWT\Security\Authentication\Token\JwtToken');
    }

    /**
     * Checks the given token for validity and sets the token authentication status
     * accordingly (success, wrong credentials or no credentials given).
     *
     * @param TokenInterface $authenticationToken The token to be authenticated
     * @throws UnsupportedAuthenticationTokenException
     * @throws \Neos\Flow\Security\Exception\InvalidArgumentForHashGenerationException
     * @throws \Neos\Flow\Security\Exception\InvalidAuthenticationStatusException
     */
    public function authenticate(TokenInterface $authenticationToken)
    {
        if (!($authenticationToken instanceof JwtToken)) {
            throw new UnsupportedAuthenticationTokenException('This provider cannot authenticate the given token.', 1417040168);
        }

        /** @var $account Account */
        $account = null;
        $credentials = $authenticationToken->getCredentials();

        if (!\is_array($credentials) || !isset($credentials['token'])) {
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
                $authenticationToken->setAccount($account);
                $this->accountRepository->update($account);
                $this->persistenceManager->whitelistObject($account);
                return;
            } else {
                $authenticationToken->setAuthenticationStatus(TokenInterface::WRONG_CREDENTIALS);
                return;
            }
        }

        if ($credentials['user_agent'] === $payload['user_agent'] && $credentials['ip_address'] === $payload['ip_address']) {
            $this->securityContext->withoutAuthorizationChecks(function () use ($payload, &$account) {
                $account = $this->accountRepository->findActiveByAccountIdentifierAndAuthenticationProviderName($payload['identifier'], $this->name);
            });
        }

        if (\is_object($account)) {
            $authenticationToken->setAuthenticationStatus(TokenInterface::AUTHENTICATION_SUCCESSFUL);
            $authenticationToken->setAccount($account);
            return;
        }

        $authenticationToken->setAuthenticationStatus(TokenInterface::WRONG_CREDENTIALS);
        return;
    }
}