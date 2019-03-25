<?php

namespace RFY\JWT\Security\Authentication\Factory;

use RFY\JWT\Security\Authentication\Token\JwtToken;
use Neos\Flow\Annotations as Flow;
use Neos\Flow\Exception;
use Neos\Flow\Http\Request;
use Neos\Flow\Security\Cryptography\HashService;
use Neos\Flow\Utility\Algorithms;
use Firebase\JWT\JWT;
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
     * @var Request
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
        $payload = [];
        $payload['identifier'] = $account->getAccountIdentifier();
        $payload['party-identifier'] = $this->persistenceManager->getIdentifierByObject($account->getParty());
        $payload['user-agent'] = $this->request->getHeader('User-Agent');
        $payload['ip-address'] = $this->request->getAttribute(Request::ATTRIBUTE_CLIENT_IP);

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