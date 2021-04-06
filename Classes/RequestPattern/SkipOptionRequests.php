<?php

namespace RFY\JWT\RequestPattern;

use Neos\Flow\Mvc\ActionRequest;
use Neos\Flow\Mvc\RequestInterface;
use Neos\Flow\Security\RequestPatternInterface;

/**
 * Class SkipOptionRequests
 * @package RFY\JWT\RequestPattern
 */
class SkipOptionRequests implements RequestPatternInterface
{

    /**
     * @var array
     */
    protected array $skipMethodsPattern = array();

    /**
     * Returns the set pattern
     *
     * @return array The set pattern
     */
    public function getPattern(): array
    {
        return $this->skipMethodsPattern;
    }

    /**
     * @param object $skipMethodsPattern
     */
    public function setPattern(object $skipMethodsPattern)
    {
        $this->skipMethodsPattern = $skipMethodsPattern;
    }

    /**
     * Matches a \Neos\Flow\Mvc\RequestInterface against its set controller object name pattern rules
     *
     * @param \Neos\Flow\Mvc\RequestInterface $request The request that should be matched
     * @return boolean TRUE if the pattern matched, FALSE otherwise
     */
    public function matchRequest(RequestInterface $request): bool
    {
        if (!$request instanceof ActionRequest) {
            return false;
        }

        foreach ($this->getPattern() as $method) {
            if ($request->getHttpRequest()->getMethod() === $method) {
                return true;
            }
        }
    }
}
