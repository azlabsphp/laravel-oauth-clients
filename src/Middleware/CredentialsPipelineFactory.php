<?php

namespace Drewlabs\Laravel\Oauth\Middleware;

use Drewlabs\Core\Helpers\Functional;

class CredentialsPipelineFactory
{
    use CreatesClientCredentials;
    use CreatesJwtClientCredentials;
    use CreatesBasicAuthCredentials;

    /**
     * @var string
     */
    private $cookie;

    /**
     * @var string
     */
    private $method;

    /**
     * @var string
     */
    private $appKey;

    /**
     * Create middleware class instance
     * 
     * @param string $appKey 
     * @param string $headerMethod 
     * @param string $cookieName 
     */
    public function __construct(string $appKey, string $headerMethod = 'jwt', string $cookieName = 'jwt-cookie')
    {
        $this->appKey = $appKey;
        $this->method = $headerMethod;
        $this->cookie = $cookieName;
    }

    /**
     * Create a callable that resolve client credentials from request instance
     * 
     * @param \Illuminate\Http\Request $request
     * 
     * @return callable 
     */
    public function create($request)
    {
        return Functional::compose(
            // Create credentials from custom cookies
            function ($credentials = null) use ($request) {
                if (null === $credentials) {
                    return $this->fromCookie($request);
                }
                return $credentials;
            },

            // Create credential from custom headers
            function ($credentials = null) use ($request) {
                if (null === $credentials) {
                    return $this->fromHeaders($request);
                }
                return $credentials;
            },

            // Create credentials from basic auth header
            function ($credentials = null) use ($request) {
                if (null === $credentials) {
                    return $this->basicAuthClientCredentials($request);
                }
                return $credentials;
            },

            // Create credentials from jwt auth headers
            function ($credentials = null) use ($request) {
                if (null === $credentials) {
                    return $this->jwtClientCredentialFromCookie($request, $this->appKey, $this->cookie ?? 'jwt-cookie');
                }
                return $credentials;
            },

            function ($credentials = null) use ($request) {
                if (null === $credentials) {
                    return $this->jwtClientFromAuthorizationHeader($request, $this->appKey, $this->cookie ?? 'jwt-cookie');
                }
                return $credentials;
            }
        );
    }
}
