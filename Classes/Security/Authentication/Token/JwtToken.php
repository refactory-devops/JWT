<?php

namespace RFY\JWT\Security\Authentication\Token;

use Neos\Flow\Annotations as Flow;
use Neos\Flow\Http\Request;
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
    protected $credentials = array('token' => '');

    /**
     * @var array
     * @Flow\InjectConfiguration(path="tokenSources")
     */
    protected $tokenSources;

    /**
     * @param ActionRequest $actionRequest The current action request
     * @return bool
     * @throws \Neos\Flow\Security\Exception\InvalidAuthenticationStatusException
     */
    public function updateCredentials(ActionRequest $actionRequest)
    {
        $httpRequest = $actionRequest->getHttpRequest();
        $token = null;

        foreach ($this->tokenSources as $tokenSource) {
            $name = $tokenSource['name'];
            if ($tokenSource['from'] === 'header') {
                if ($httpRequest->hasHeader($name)) {
                    $token = $httpRequest->getHeader($name);
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
            $this->credentials['encoded'] = $token;
            $this->setAuthenticationStatus(self::AUTHENTICATION_NEEDED);
            return true;
        }

        $this->setAuthenticationStatus(self::NO_CREDENTIALS_GIVEN);
        return false;
    }

    /**
     * @return string
     */
    public function getEncodedJwt() {
        return $this->credentials['encoded'];
    }

    /**
     * Returns a string representation of the token for logging purposes.
     *
     * @return string The username credential
     */
    public function __toString()
    {
        return 'TOKEN: "' . \substr($this->credentials['token'], 0, 30) . '..."';
    }
}