<?php
declare(strict_types=1);

namespace RFY\JWT\Http;

use Neos\Flow\Security\Authentication\AuthenticationManagerInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;

final class GetJwtTokenMiddleware implements MiddlewareInterface
{
    private AuthenticationManagerInterface $authenticationManager;

    public function __construct(AuthenticationManagerInterface $authenticationManager)
    {
        $this->authenticationManager = $authenticationManager;
    }

    public function process(ServerRequestInterface $request, RequestHandlerInterface $next): ResponseInterface
    {
        $this->authenticationManager->isAuthenticated();
        return $next->handle($request);
    }
}
