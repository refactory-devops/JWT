<?php

namespace RFY\JWT\Security;

use Neos\Flow\Security\Account;
use Neos\Party\Domain\Model\AbstractParty;

/**
 * Class JwtAccount
 * @package RFY\JWT\Security
 */
class JwtAccount extends Account
{
    /**
     * @var \stdClass
     */
    protected $claims;

    /**
     * @var AbstractParty
     */
    protected $party;

    /**
     * @param $claims
     */
    public function setClaims($claims)
    {
        $this->claims = $claims;
    }

    /**
     * @param AbstractParty $party
     */
    public function setParty(AbstractParty $party)
    {
        $this->party = $party;
    }

    /**
     * @return AbstractParty
     */
    public function getParty(): AbstractParty
    {
        return $this->party;
    }

    /**
     * @param $name
     * @param $args
     * @return mixed
     */
    public function __call($name, $args)
    {
        if (\substr($name, 0, 3) === 'get') {
            $name = \lcfirst(\substr($name, 3));
            return $this->claims->{$name};
        }
        throw new \BadMethodCallException($name . ' is not callable on this object');
    }
}
