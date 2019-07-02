<?php
declare(strict_types=1);

namespace RFY\JWT\Http;

use Neos\Flow\Annotations as Flow;
use Neos\Flow\Http\Component\ComponentContext;
use Neos\Flow\Http\Component\ComponentInterface;
use Neos\Flow\Http\Cookie;
use Neos\Flow\Security\Context as SecurityContext;
use Psr\Log\LoggerInterface;
use RFY\JWT\Security\Authentication\Factory\TokenFactory;
use RFY\JWT\Security\Authentication\Token\JwtToken;

/**
 * Class SetJwtTokenComponent
 * @package RFY\JWT\Http
 */
final class SetJwtTokenComponent implements ComponentInterface
{
    /**
     * @Flow\Inject
     * @var SecurityContext
     */
    protected $securityContext;

    /**
     * @Flow\Inject
     * @var LoggerInterface
     */
    protected $logger;

    /**
     * @var array
     */
    private $options;

    /**
     * SetJwtTokenComponent constructor.
     * @param array|null $options
     */
    public function __construct(array $options = null)
    {
        $this->options = $options;
    }

    /**
     * @param ComponentContext $componentContext
     */
    public function handle(ComponentContext $componentContext): void
    {
        if (!$this->securityContext->isInitialized() && !$this->securityContext->canBeInitialized()) {
            $this->logger->debug(sprintf('JWT package: (%s) Cannot send JWT because the security context could not be initialized.', get_class($this)));
            return;
        }
        if (!$this->isJWTAuthentication()) {
            return;
        }


        $account = $this->securityContext->getAccountByAuthenticationProviderName($this->options['authenticationProviderName']);
        if ($account === null) {
            $this->logger->info(sprintf('JWT package: (%s) No Flow account found for %s, removing JWT cookie.', \get_class($this), $this->options['authenticationProviderName']));
            return;
        }

        $this->setJwtToken($componentContext);
    }

    /**
     * @return bool
     */
    private function isJWTAuthentication(): bool
    {
        foreach ($this->securityContext->getAuthenticationTokensOfType(JwtToken::class) as $token) {
            if ($token->getAuthenticationProviderName() === $this->options['authenticationProviderName']) {
                return true;
            }
        }
        return false;
    }

    /**
     * @param ComponentContext $componentContext
     */
    private function setJwtToken(ComponentContext $componentContext): void
    {
        $tokenFactory = new TokenFactory($componentContext->getHttpRequest());
        $componentContext->replaceHttpResponse($componentContext->getHttpResponse()->withAddedHeader('Authorization', 'Bearer ' . $tokenFactory->getJsonWebToken()));
    }
}
