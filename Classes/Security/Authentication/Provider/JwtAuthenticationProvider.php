<?php

namespace RFY\JWT\Security\Authentication\Provider;

use Firebase\JWT\ExpiredException;
use Neos\Flow\Annotations as Flow;
use Neos\Flow\Security\Account;
use Neos\Flow\Security\Authentication\Provider\AbstractProvider;
use Neos\Flow\Security\Authentication\TokenInterface;
use Neos\Flow\Security\Exception\UnsupportedAuthenticationTokenException;
use Neos\Flow\Security\Policy\PolicyService;
use RFY\JWT\Security\Authentication\Token\JwtToken;
use RFY\JWT\Security\JwtAccount;
use RFY\JWT\Service\JwtService;

/**
 * An authentication provider that authenticates ApiTokens
 */
class JwtAuthenticationProvider extends AbstractProvider
{
    /**
     * @var array
     * @Flow\InjectConfiguration(path="claimMapping")
     */
    protected array $claimMapping;

    /**
     * @var JwtService
     * @Flow\Inject()
     */
    protected $jwtService;

    /**
     * @var PolicyService
     * @Flow\Inject
     */
    protected $policyService;

    /**
     * @Flow\Inject
     * @var \Neos\Party\Domain\Repository\PartyRepository
     */
    protected $partyRepository;

    /**
     * Returns the class names of the tokens this provider can authenticate.
     *
     * @return array
     */
    public function getTokenClassNames(): array
    {
        return [JwtToken::class];
    }

    /**
     * Checks the given token for validity and sets the token authentication status
     * accordingly (success, wrong credentials or no credentials given).
     *
     * @param TokenInterface $authenticationToken The token to be authenticated
     * @throws UnsupportedAuthenticationTokenException
     * @throws \Neos\Flow\Security\Exception\InvalidAuthenticationStatusException|\Neos\Flow\Security\Exception\NoSuchRoleException
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
            // todo check expirationdate
        } catch (ExpiredException $expired) {
            $authenticationToken->setAuthenticationStatus(TokenInterface::WRONG_CREDENTIALS);
            return;
        } catch (\Exception $err) {
            $authenticationToken->setAuthenticationStatus(TokenInterface::WRONG_CREDENTIALS);
            return;
        }

        $account = new JwtAccount();
        $account->setClaims($claims);
        $account->setAuthenticationProviderName('JwtAuthenticationProvider');
        $account->setParty($this->partyRepository->findByIdentifier($claims->{'identifier'}));

        if (is_array($this->claimMapping['inheritRolesFromOtherProviders']) && count($this->claimMapping['inheritRolesFromOtherProviders']) > 0) {
            /** @var Account $otherAccount */
            foreach ($account->getParty()->getAccounts() as $otherAccount) {
                if (strstr($otherAccount->getAuthenticationProviderName(), implode(',', $this->claimMapping['inheritRolesFromOtherProviders']))) {
                    foreach ($otherAccount->getRoles() as $role) {
                        $account->addRole($role);
                    }
                    break;
                }
            }
        }

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
