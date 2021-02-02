<?php

namespace RFY\JWT\Security\Authentication\Token;

use Neos\Flow\Annotations as Flow;
use Neos\Flow\Mvc\ActionRequest;
use Neos\Flow\Security\Authentication\Token\AbstractToken;
use Neos\Flow\Security\Authentication\Token\SessionlessTokenInterface;

/**
 * An authentication token used for simple username and password authentication.
 */
class JwtToken extends AbstractToken implements SessionlessTokenInterface
{

    /**
     * The jwt credentials
     *
     * @var array
     * @Flow\Transient
     */
    protected $credentials = ['token' => ''];

    /**
     * @var array
     * @Flow\InjectConfiguration(path="tokenSources")
     */
    protected $tokenSources;

    /**
     * @param ActionRequest $actionRequest The current action request
     * @return void
     * @throws \Neos\Flow\Security\Exception\InvalidAuthenticationStatusException
     */
    public function updateCredentials(ActionRequest $actionRequest): void
    {
        $httpRequest = $actionRequest->getHttpRequest();
        $token = null;

        foreach ($this->tokenSources as $tokenSource) {
            $name = $tokenSource['name'];
            if ($tokenSource['from'] === 'header') {
                if ($httpRequest->hasHeader($name)) {
                    $token = $httpRequest->getHeader($name)[0];
                    if (\strpos($token, 'Bearer ') === 0) {
                        $token = \substr($token, 7);
                    }
                    break;
                }
            } elseif ($tokenSource['from'] === 'cookie') {
                if ($httpRequest->hasCookie($name)) {
                    $token = $httpRequest->getCookie($name)->getValue();
                    break;
                }
            } elseif ($tokenSource['from'] === 'query') {
                if ($httpRequest->hasArgument($name)) {
                    $token = $httpRequest->getArgument($name);
                    break;
                }
            }
        }

        if (NULL !== $token) {
            $this->credentials['token'] = $token;
            $this->setAuthenticationStatus(self::AUTHENTICATION_NEEDED);
            return;
        }

        $this->setAuthenticationStatus(self::NO_CREDENTIALS_GIVEN);
    }

    /**
     * @return string
     */
    public function getEncodedJwt()
    {
        return $this->credentials['token'];
    }

    /**
     * Returns a string representation of the token for logging purposes.
     *
     * @return string The username credential
     */
    public function __toString()
    {
        return 'JWT: "' . \substr($this->credentials['token'], 0, 30) . '..."';
    }
}
