<?php
declare(strict_types=1);

namespace RFY\JWT\Http;

use Neos\Flow\Annotations as Flow;
use Neos\Flow\Http\Cookie;
use Neos\Flow\Security\Context as SecurityContext;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;
use Psr\Log\LoggerInterface;
use RFY\JWT\Security\Authentication\Factory\CookieFactory;
use RFY\JWT\Security\Authentication\Factory\TokenFactory;
use RFY\JWT\Security\Authentication\Token\JsonWebToken;
use RFY\JWT\Security\Authentication\Token\JwtToken;

final class SetJwtTokenMiddleware implements MiddlewareInterface
{
    private array $jwtAuthenticationProviderName;
    private array $jsonWebAuthenticationProviderName;
    private SecurityContext $securityContext;
    private LoggerInterface $logger;

    /**
     * @var array
     * @Flow\InjectConfiguration(path="tokenStrategy")
     */
    protected array $tokenStrategy;

    /**
     * @var array
     * @Flow\InjectConfiguration(path="tokenSources")
     */
    protected array $tokenSources;

    /**
     * @Flow\Inject
     * @var CookieFactory
     */
    protected $cookieFactory;

    public function __construct(array $jwtAuthenticationProviderName, array $jsonWebAuthenticationProviderName, SecurityContext $securityContext, LoggerInterface $logger)
    {
        $this->jwtAuthenticationProviderName = $jwtAuthenticationProviderName;
        $this->jsonWebAuthenticationProviderName = $jsonWebAuthenticationProviderName;
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

        $authenticationProviderName = $this->getJWTAuthenticationProviderName();

        if ($authenticationProviderName === null) {
            return $response;
        }

        $account = $this->securityContext->getAccountByAuthenticationProviderName($authenticationProviderName);

        if ($account === null) {
            foreach ($this->tokenSources as $source) {
                if (!empty($source['from']) && !empty($source['name'])) {
                    $response = $response->withAddedHeader('Set-Cookie', (string) $this->cookieFactory->getBlankJwtCookie($source['name']));
                }
            }
            $this->logger->info(\sprintf('JWT package: (%s) No Flow account found for %s, removing JWT cookie.', \get_class($this), implode(',', $this->jwtAuthenticationProviderName)));
            return $response;
        }

        $tokenFactory = new TokenFactory($request);
        $token = $tokenFactory->getJsonWebToken();

        foreach ($this->tokenSources as $source) {
            if (!empty($source['from']) && !empty($source['name'])) {
                if ($source['from'] === 'cookie' && !isset($request->getCookieParams()[$source['name']])) {
                    $response = $response->withAddedHeader('Set-Cookie', (string) $this->cookieFactory->getJwtCookie($source['name'], $token));
                }
                if ($source['from'] === 'header') {
                    $response = $response->withAddedHeader($source['name'], 'Bearer ' . $token);
                }
            }
        }

        return $response;
    }

    /**
     * @return string|null
     */
    private function getJWTAuthenticationProviderName(): ?string
    {

        foreach ($this->securityContext->getAuthenticationTokensOfType(JwtToken::class) as $token) {
            if (in_array($token->getAuthenticationProviderName(), $this->jwtAuthenticationProviderName)) {
                return $token->getAuthenticationProviderName();
            }
        }
        foreach ($this->securityContext->getAuthenticationTokensOfType(JsonWebToken::class) as $token) {
            if (in_array($token->getAuthenticationProviderName(), $this->jsonWebAuthenticationProviderName)) {
                return $token->getAuthenticationProviderName();
            }
        }

        return null;
    }

}
