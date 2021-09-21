<?php

namespace RFY\JWT\Security\Authentication\Factory;

use Neos\Flow\Annotations as Flow;
use Neos\Flow\Http\Cookie;

/**
 * Class TokenFactory
 *
 * @package RFY\JWT\Domain\Factory
 * @Flow\Scope("singleton")
 */
class CookieFactory
{

    /**
     * @Flow\InjectConfiguration(package="Neos.Flow", path="session")
     * @var array
     */
    protected $sessionSettings;

    public function getJwtCookie(string $name, string $jwt): Cookie
    {
        return new Cookie(
            $name,
            trim(urldecode($jwt), '"'),
            0,
            $this->sessionSettings['cookie']['lifetime'],
            $this->sessionSettings['cookie']['domain'],
            $this->sessionSettings['cookie']['path'],
            $this->sessionSettings['cookie']['secure'],
            $this->sessionSettings['cookie']['httponly'],
            'strict'
        );
    }

    public function getBlankJwtCookie($name): Cookie
    {
        return new Cookie($name, '', 1, null, null, '/', false, true, 'strict');
    }
}
