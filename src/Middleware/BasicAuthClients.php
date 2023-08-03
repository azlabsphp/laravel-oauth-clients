<?php

namespace Drewlabs\Laravel\Oauth\Middleware;

use Closure;
use Drewlabs\Oauth\Clients\Contracts\CredentialsIdentityValidator;
use Drewlabs\Oauth\Clients\Exceptions\AuthorizationException;
use InvalidArgumentException;

class BasicAuthClients
{
    use CreatesBasicAuthCredentials;

    /**
     * @var CredentialsIdentityValidator
     */
    private $validator;

    /**
     * Creates class instance
     * 
     * @param CredentialsIdentityValidator $validator 
     */
    public function __construct(CredentialsIdentityValidator $validator)
    {
        $this->validator = $validator;
    }


    /**
     * Handle an incoming request
     * 
     * @param \Illuminate\Http\Request $request 
     * @param Closure $next 
     * @param mixed $scopes 
     * @return mixed 
     * @throws InvalidArgumentException 
     * @throws AuthorizationException 
     */
    public function handle($request, Closure $next, ...$scopes)
    {
        if (null === ($credentials = $this->basicAuthClientCredentials($request))) {
            // throw not found exception if base64 is null or false
            throw new AuthorizationException('basic auth string not found', 401);
        }

        try {
            // pass the server request through credentials validation layer
            $this->validator->validate($credentials, $scopes, $this->getRequestIp($request));
            // next request
            return $next($request);
        } catch (\Throwable $e) {
            throw new AuthorizationException($e->getMessage(), 401);
        }
    }
}
