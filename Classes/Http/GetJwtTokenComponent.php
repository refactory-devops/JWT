<?php
declare(strict_types=1);

namespace RFY\JWT\Http;

use Neos\Flow\Annotations as Flow;
use Neos\Flow\Http\Component\ComponentContext;
use Neos\Flow\Http\Component\ComponentInterface;
use Neos\Flow\Security\Authentication\AuthenticationManagerInterface;

/**
 * Class SetJwtTokenComponent
 * @package RFY\JWT\Http
 */
final class GetJwtTokenComponent implements ComponentInterface
{
    /**
     * @Flow\Inject
     * @var AuthenticationManagerInterface
     */
    protected $authenticationManager;

    /**
     * @param ComponentContext $componentContext
     */
    public function handle(ComponentContext $componentContext): void
    {
        $this->authenticationManager->isAuthenticated();
    }
}
