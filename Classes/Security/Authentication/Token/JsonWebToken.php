<?php

namespace RFY\JWT\Security\Authentication\Token;

use Neos\Flow\Annotations as Flow;
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
     * @return void
     * @throws \Neos\Flow\Security\Exception\InvalidAuthenticationStatusException
     */
    public function updateCredentials(ActionRequest $actionRequest): void
    {
        if ($actionRequest->getHttpRequest()->getMethod() === 'OPTIONS') {
            return;
        }

        $body = $actionRequest->getHttpRequest()->getBody();
        $contentType = $actionRequest->getHttpRequest()->getHeader('Content-Type');

        $authorizationArguments = \json_decode($body);
        if (\in_array('application/json', $contentType) && \json_last_error() === JSON_ERROR_NONE) {
            if (isset($authorizationArguments->{'username'}) && isset($authorizationArguments->{'password'})) {
                $this->credentials['username'] = $authorizationArguments->{'username'};
                $this->credentials['password'] = $authorizationArguments->{'password'};
                $this->setAuthenticationStatus(self::AUTHENTICATION_NEEDED);
                return;
            }
        }
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
