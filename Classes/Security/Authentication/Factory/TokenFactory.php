<?php

namespace RFY\JWT\Security\Authentication\Factory;

use Neos\Flow\Annotations as Flow;
use GuzzleHttp\Psr7\ServerRequest;
use RFY\JWT\Security\JwtAccount;
use RFY\JWT\Service\JwtService;

/**
 * Class TokenFactory
 *
 * @package RFY\JWT\Domain\Factory
 * @Flow\Scope("singleton")
 */
class TokenFactory
{

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
     * @var \Neos\Flow\Persistence\PersistenceManagerInterface
     */
    protected $persistenceManager;

    /**
     * @Flow\Inject()
     * @var JwtService
     */
    protected $jwtService;

    /**
     * @var ServerRequest
     */
    protected $request;

    /**
     * @param $request
     */
    public function __construct($request)
    {
        $this->request = $request;
    }

    /**
     * @return string
     */
    public function getJsonWebToken()
    {
        /** @var JwtAccount $account */
        $account = $this->securityContext->getAccount();
        $payload['username'] = $account->getAccountIdentifier();
        $payload['identifier'] = $this->persistenceManager->getIdentifierByObject($account->getParty());
        $payload['user-agent'] = $this->request->getHeader('User-Agent');
        $payload['ip-address'] = $this->request->getAttribute('clientIpAddress');

        if ($account->getCreationDate() instanceof \DateTime) {
            $payload['creationDate'] = $account->getCreationDate()->getTimestamp();
        }

        // TODO Add refresh token + expire date
        if ($account->getExpirationDate() instanceof \DateTime) {
            $payload['expirationDate'] = $account->getExpirationDate()->getTimestamp();
        }
        return $this->jwtService->createJsonWebToken($payload);
    }
}
