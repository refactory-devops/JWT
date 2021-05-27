<?php
declare(strict_types=1);

namespace RFY\JWT\Http;

use Neos\Flow\Security\Context as SecurityContext;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;
use Psr\Log\LoggerInterface;
use RFY\JWT\Security\Authentication\Factory\TokenFactory;
use RFY\JWT\Security\Authentication\Token\JwtToken;

final class SetJwtTokenMiddleware implements MiddlewareInterface
{
    private string $authenticationProviderName;
    private SecurityContext $securityContext;
    private LoggerInterface $logger;

    public function __construct(string $authenticationProviderName, SecurityContext $securityContext, LoggerInterface $logger)
    {
        $this->authenticationProviderName = $authenticationProviderName;
        $this->securityContext = $securityContext;
        $this->logger = $logger;
    }

    public function process(ServerRequestInterface $request, RequestHandlerInterface $next): ResponseInterface
    {
        $response = $next->handle($request);
        if (!$this->securityContext->isInitialized() && !$this->securityContext->canBeInitialized()) {
            $this->logger->debug(\sprintf('JWT package: (%s) Cannot send JWT because the security context could not be initialized.', \get_class($this)));
            return $response;
        }
        if (!$this->isJWTAuthentication()) {
            return $response;
        }

        $account = $this->securityContext->getAccountByAuthenticationProviderName($this->authenticationProviderName);
        if ($account === null) {
            $this->logger->info(\sprintf('JWT package: (%s) No Flow account found for %s, removing JWT cookie.', \get_class($this), $this->authenticationProviderName));
            return $response;
        }

        $tokenFactory = new TokenFactory($request);
        return $response->withAddedHeader('Authorization', 'Bearer ' . $tokenFactory->getJsonWebToken());
    }

    /**
     * @return bool
     */
    private function isJWTAuthentication(): bool
    {
        foreach ($this->securityContext->getAuthenticationTokensOfType(JwtToken::class) as $token) {
            if ($token->getAuthenticationProviderName() === $this->authenticationProviderName) {
                return true;
            }
        }
        return false;
    }
}
