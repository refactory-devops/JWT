<?php

namespace RFY\JWT\Security\Authentication\Factory;

use Neos\Flow\Annotations as Flow;
use GuzzleHttp\Psr7\ServerRequest;
use Neos\Flow\Persistence\PersistenceManagerInterface;
use Neos\Flow\Security\AccountFactory;
use Neos\Flow\Security\AccountRepository;
use Neos\Flow\Security\Context;
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
     * @var Context
     * @Flow\Inject
     */
    protected $securityContext;

    /**
     * @Flow\Inject
     * @var AccountRepository
     */
    protected $accountRepository;

    /**
     * @Flow\Inject
     * @var AccountFactory
     */
    protected $accountFactory;

    /**
     * @Flow\Inject
     * @var PersistenceManagerInterface
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
     * @var int
     * @Flow\InjectConfiguration(path="tokenLifetime")
     */
    protected $tokenLifetime;

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
    public function getJsonWebToken(): string
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

        if ($account->getExpirationDate() instanceof \DateTime) {
            $payload['accountExpirationDate'] = $account->getExpirationDate()->getTimestamp();
        }

        if ($this->tokenLifetime > 0) {
            $payload['exp'] = (new \DateTime())->getTimestamp() + $this->tokenLifetime;
        }

        if (array_key_exists('accountExpirationDate', $payload) && array_key_exists('exp', $payload)) {
            if ($payload['accountExpirationDate'] < $payload['exp']) {
                $payload['exp'] = $payload['accountExpirationDate'];
            }
        }
        return $this->jwtService->createJsonWebToken($payload);
    }

}
