<?php

namespace App\Http\Middleware;

use Closure;
use Drewlabs\Laravel\Oauth\Middleware\CreatesJwtClientCredentials;
use Drewlabs\Oauth\Clients\Contracts\CredentialsIdentityValidator;
use Drewlabs\Oauth\Clients\Exceptions\AuthorizationException;
use InvalidArgumentException;

class JwtAuthClients
{

    use CreatesJwtClientCredentials;

    /**
     * @var CredentialsIdentityValidator
     */
    private $validator;

    /**
     * @var string
     */
    private $cookieName;

    /**
     * @var string
     */
    private $headerMethod;

    /**
     * @var string
     */
    private $appKey;

    /**
     * Creates middlewate instance
     * 
     * @param CredentialsIdentityValidator $validator 
     * @param string $appKey 
     * @param string $headerMethod 
     * @param string $cookieName 
     * @return void 
     */
    public function __construct(CredentialsIdentityValidator $validator, string $appKey, string $headerMethod = 'jwt', string $cookieName = 'jwt-cookie')
    {
        $this->validator = $validator;
        $this->appKey = $appKey;
        $this->headerMethod = $headerMethod;
        $this->cookieName = $cookieName;
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
        // Get credentials from request cookies
        $credentials = $this->jwtClientCredentialFromCookie($request, $this->appKey, $this->cookieName);

        // Get credentials from header
        if (null === $credentials) {
            $credentials = $this->jwtClientFromAuthorizationHeader($request, $this->appKey, $this->headerMethod);
        }

        if (null === $credentials) {
            // throw not found exception if base64 is null or false
            throw new AuthorizationException('jwt auth string not found', 401);
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
