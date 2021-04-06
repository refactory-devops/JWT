<?php
namespace RFY\JWT\Tests\Functional;

use GuzzleHttp\Psr7\Uri;
use Neos\Flow\Http\ContentStream;
use Neos\Flow\Security\AccountFactory;
use Neos\Flow\Security\AccountRepository;
use Neos\Flow\Tests\FunctionalTestCase;
use Neos\Party\Domain\Model\Person;
use Neos\Party\Domain\Model\PersonName;
use Neos\Party\Domain\Repository\PartyRepository;
use Psr\Http\Message\ServerRequestFactoryInterface;

/**
 * Testcase for Authentication
 */
class AuthenticationTest extends FunctionalTestCase
{
    /**
     * @var boolean
     */
    protected $testableSecurityEnabled = true;

    /**
     * @var boolean
     */
    protected static $testablePersistenceEnabled = true;

    /**
     * @var ServerRequestFactoryInterface
     */
    protected $serverRequestFactory;

    /**
     * @return void
     */
    protected function setUp(): void
    {
        parent::setUp();
        $partyRepository = $this->objectManager->get(PartyRepository::class);
        $person = $this->objectManager->get(Person::class);
        $name = $this->objectManager->get(PersonName::class);
        $name->setFirstName('Firstname');
        $name->setLastName('Lastname');
        $person->setName($name);
        $accountRepository = $this->objectManager->get(AccountRepository::class);
        $accountFactory = $this->objectManager->get(AccountFactory::class);
        $account = $accountFactory->createAccountWithPassword('functional_test_account', 'a_very_secure_long_password', ['Neos.Flow:Administrator'], 'DefaultProvider');
        $accountRepository->add($account);
        $person->addAccount($account);
        $partyRepository->add($person);
        $this->persistenceManager->persistAll();
        $this->persistenceManager->clearState();

        $this->serverRequestFactory = $this->objectManager->get(ServerRequestFactoryInterface::class);
    }

    /**
     * @test
     */
    public function optionsRequestTokenAuth()
    {
        $uri = new Uri('http://localhost/authentication/token-auth');
        $request = $this->serverRequestFactory->createServerRequest('OPTIONS', $uri);
        $request->withHeader('Content-Type', 'application/json');
        $response = $this->browser->sendRequest($request);

        self::assertEquals(204, $response->getStatusCode());
    }

    /**
     * @test
     */
    public function successfulJWTAuthentication()
    {
        $request = $this->serverRequestFactory->createServerRequest('POST', new Uri('http://localhost/authentication/token-auth'))
            ->withBody(ContentStream::fromContents('{"username":"functional_test_account","password":"a_very_secure_long_password"}'))
            ->withHeader('Content-Type', 'application/json');
        $response = $this->browser->sendRequest($request);
        self::assertEquals(200, $response->getStatusCode());
    }

    /**
     * @test
     */
    public function authenticationFailure()
    {
        $uri = new Uri('http://localhost/authentication/token-auth');

        $arguments = [];
        $arguments['username'] = 'unknown_user';
        $arguments['password'] = 'a_wrong_password';

        $request = $this->serverRequestFactory->createServerRequest('POST', $uri, $arguments);
        $request->withBody(ContentStream::fromContents(json_encode($arguments)));
        $request->withHeader('Content-Type', 'application/json');
        $response = $this->browser->sendRequest($request);

        self::assertEquals(401, $response->getStatusCode());
    }
}
