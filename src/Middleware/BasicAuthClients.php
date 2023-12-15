<?php

namespace Drewlabs\Laravel\Oauth\Clients\Middleware;

use Closure;
use Drewlabs\Laravel\Oauth\Clients\ServerRequest;
use Drewlabs\Oauth\Clients\BasicAuthorizationCredentialsFactory;
use Drewlabs\Oauth\Clients\Contracts\CredentialsIdentityValidator;
use Drewlabs\Oauth\Clients\Exceptions\AuthorizationException;
use InvalidArgumentException;

class BasicAuthClients
{
    /**
     * @var CredentialsIdentityValidator
     */
    private $validator;

    /**
     * @var BasicAuthorizationCredentialsFactory
     */
    private $factory;

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
        BasicAuthorizationCredentialsFactory $factory
    ) {
        $this->validator = $validator;
        $this->factory = $factory;
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
        if (null === ($credentials = $this->factory->create($request))) {
            // throw not found exception if base64 is null or false
            throw new AuthorizationException('basic auth string not found', 401);
        }

        try {
            // pass the server request through credentials validation layer
            $this->validator->validate($credentials, $scopes, $this->serverRequest->getRequestIp($request));
            // Added __X_REQUEST_CLIENT__ to request attributes
            $request->attributes->add(['__X_REQUEST_CLIENT__' => $credentials]);
            // next request
            return $next($request);
        } catch (\Throwable $e) {
            throw new AuthorizationException($e->getMessage(), 401);
        }
    }
}
