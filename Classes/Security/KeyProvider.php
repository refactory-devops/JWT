<?php

namespace RFY\JWT\Security;

use Neos\Flow\Annotations as Flow;
use Neos\Cache\Frontend\FrontendInterface;

/**
 * @Flow\Scope("singleton")
 */
class KeyProvider
{
    /**
     * @var string
     * @Flow\InjectConfiguration(path="keyUrl")
     */
    protected $keyUrl;

    /**
     * @var string
     * @Flow\InjectConfiguration(path="key")
     */
    protected $key;

    /**
     * @var FrontendInterface
     * @Flow\Inject
     */
    protected $cache;

    /**
     * @return string
     */
    public function getPublicKey(): string
    {
        if ($this->key) {
            return $this->key;
        }
        $cacheKey = \sha1($this->keyUrl);
        if ($this->cache->has($cacheKey)) {
            return $this->cache->get($cacheKey);
        }
        $key = @file_get_contents($this->keyUrl);
        $this->cache->set($cacheKey, $key);
        return $key;
    }
}
