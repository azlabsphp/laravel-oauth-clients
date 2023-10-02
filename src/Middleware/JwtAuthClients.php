<?php

namespace Drewlabs\Laravel\Oauth\Clients\Middleware;

use Closure;
use Drewlabs\Laravel\Oauth\Clients\ServerRequest;
use Drewlabs\Oauth\Clients\Contracts\CredentialsIdentityValidator;
use Drewlabs\Oauth\Clients\Exceptions\AuthorizationException;
use Drewlabs\Oauth\Clients\JwtAuthorizationHeaderCredentialsFactory;
use Drewlabs\Oauth\Clients\JwtCookieCredentialsFactory;
use InvalidArgumentException;

class JwtAuthClients
{
    /**
     * @var CredentialsIdentityValidator
     */
    private $validator;
    
    /**
     * @var JwtAuthorizationHeaderCredentialsFactory
     */
    private $jwtHeaderFactory;

    /**
     * 
     * @var JwtCookieCredentialsFactory
     */
    private $jwtCookieFactory;

    /**
     * @var ServerRequest
     */
    private $serverRequest;

    /**
     * Creates class instance
     * 
     * @param CredentialsIdentityValidator $validator 
     */
    public function __construct(
        ServerRequest $serverRequest,
        CredentialsIdentityValidator $validator,
        JwtAuthorizationHeaderCredentialsFactory $jwtHeaderFactory,
        JwtCookieCredentialsFactory $jwtCookieFactory
    ) {
        $this->validator = $validator;
        $this->jwtHeaderFactory = $jwtHeaderFactory;
        $this->jwtCookieFactory = $jwtCookieFactory;
        $this->serverRequest = $serverRequest;
    }


    /**
     * Handle an incoming request
     * 
     * @param mixed $request 
     * @param Closure $next 
     * @param mixed $scopes 
     * @return mixed 
     * @throws InvalidArgumentException 
     * @throws AuthorizationException 
     */
    public function handle($request, callable $next, ...$scopes)
    {
        // Get credentials from request cookies
        $credentials = $this->jwtCookieFactory->create($request);

        // Get credentials from header
        if (null === $credentials) {
            $credentials = $this->jwtHeaderFactory->create($request);
        }

        if (null === $credentials) {
            // throw not found exception if base64 is null or false
            throw new AuthorizationException('jwt auth string not found', 401);
        }

        try {
            // pass the server request through credentials validation layer
            $this->validator->validate($credentials, $scopes, $this->serverRequest->getRequestIp($request));
            // next request
            return $next($request);
        } catch (\Throwable $e) {
            throw new AuthorizationException($e->getMessage(), 401);
        }
    }
}
