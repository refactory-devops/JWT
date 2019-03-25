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
class JsonWebToken extends AbstractToken implements SessionlessTokenInterface
{

    /**
     * The jwt credentials
     *
     * @var array
     * @Flow\Transient
     */
    protected $credentials = ['token' => ''];

    /**
     * @param ActionRequest $actionRequest The current action request
     * @return bool|void
     * @throws \Neos\Flow\Security\Exception\InvalidAuthenticationStatusException
     */
    public function updateCredentials(ActionRequest $actionRequest)
    {
        if ($actionRequest->getHttpRequest()->getMethod() === 'OPTIONS') {
            return;
        }

        $body = $actionRequest->getHttpRequest()->getBody();
        $contentType = $actionRequest->getHttpRequest()->getHeaders()->get('Content-Type');

        $authorizationArguments = \json_decode($body);
        if ($contentType === 'application/json' && \json_last_error() === JSON_ERROR_NONE) {
            if (isset($authorizationArguments->{'username'}) && isset($authorizationArguments->{'password'})) {
                $this->credentials['username'] = $authorizationArguments->{'username'};
                $this->credentials['password'] = $authorizationArguments->{'password'};
                $this->setAuthenticationStatus(self::AUTHENTICATION_NEEDED);
                return;
            }
        }

//        $authorizationHeader = $actionRequest->getHttpRequest()->getHeaders()->get('Authorization');
//
//        if (\substr($authorizationHeader, 0, 6) === 'Bearer') {
//            $this->credentials['token'] = \substr($authorizationHeader, 7);
//            $this->credentials['user_agent'] = $actionRequest->getHttpRequest()->getHeader('User-Agent');
//            $this->credentials['ip_address'] = $actionRequest->getHttpRequest()->getAttribute(Request::ATTRIBUTE_CLIENT_IP);
//            $this->setAuthenticationStatus(self::AUTHENTICATION_NEEDED);
//            return;
//        } else {
//            $this->credentials = array('token' => NULL);
//            $this->authenticationStatus = self::NO_CREDENTIALS_GIVEN;
//            return;
//        }
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