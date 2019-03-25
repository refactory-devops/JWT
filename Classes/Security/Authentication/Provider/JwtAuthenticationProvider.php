<?php

namespace RFY\JWT\Security\Authentication\Provider;

use Firebase\JWT\ExpiredException;
use Neos\Flow\Annotations as Flow;
use Neos\Flow\Log\PsrSystemLoggerInterface;
use Neos\Flow\Security\Account;
use Neos\Flow\Security\Authentication\Provider\AbstractProvider;
use Neos\Flow\Security\Authentication\TokenInterface;
use Neos\Flow\Security\Exception\UnsupportedAuthenticationTokenException;
use Neos\Flow\Security\Policy\PolicyService;
use RFY\JWT\Security\KeyProvider;
use RFY\JWT\Security\Authentication\Token\JwtToken;
use RFY\JWT\Security\JwtAccount;
use RFY\JWT\Service\JwtService;

/**
 * An authentication provider that authenticates ApiTokens
 */
class JwtAuthenticationProvider extends AbstractProvider
{

    /**
     * @var KeyProvider
     * @Flow\Inject
     */
    protected $keyProvider;

    /**
     * @var array
     * @Flow\InjectConfiguration(path="claimMapping")
     */
    protected $claimMapping;

    /**
     * @var JwtService
     * @Flow\Inject()
     */
    protected $jwtService;

    /**
     * @var PsrSystemLoggerInterface
     * @Flow\Inject
     */
    protected $systemLogger;

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
    public function getTokenClassNames()
    {
        return [JwtToken::class];
    }

    /**
     * Returns true if the given token can be authenticated by this provider
     *
     * @param TokenInterface $token The token that should be authenticated
     * @return boolean true if the given token class can be authenticated by this provider
     */
    public function canAuthenticate(TokenInterface $token): bool
    {
        return ($token instanceof JwtToken);
    }

    /**
     * Checks the given token for validity and sets the token authentication status
     * accordingly (success, wrong credentials or no credentials given).
     *
     * @param TokenInterface $authenticationToken The token to be authenticated
     * @throws UnsupportedAuthenticationTokenException
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

        try {
            $encoded = $authenticationToken->getEncodedJwt();
            $claims = $this->jwtService->decodeJsonWebToken($encoded);
        } catch (ExpiredException $expired) {
            $authenticationToken->setAuthenticationStatus(TokenInterface::WRONG_CREDENTIALS);
            return;
        } catch (\Exception $err) {
            $this->systemLogger->error($err->getMessage());
            $authenticationToken->setAuthenticationStatus(TokenInterface::WRONG_CREDENTIALS);
            return;
        }

        $account = new JwtAccount();
        $account->setClaims($claims);
//        $account->setAccountIdentifier($claims->sub);
        $account->setAuthenticationProviderName('JwtAuthenticationProvider');

        $rolesClaim = $this->claimMapping['roles'];
        foreach ($rolesClaim as $key => $roleClaim) {
            $flowRoleName = $this->claimMapping['roles'][$key];
            $role = $this->policyService->getRole($flowRoleName);
            $account->addRole($role);
        }

        $authenticationToken->setAccount($account);
        $authenticationToken->setAuthenticationStatus(TokenInterface::AUTHENTICATION_SUCCESSFUL);
    }
}