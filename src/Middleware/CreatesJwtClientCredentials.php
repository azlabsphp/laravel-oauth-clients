<?php

namespace Drewlabs\Laravel\Oauth\Clients\Middleware;

use Drewlabs\Oauth\Clients\Exceptions\InvalidTokenException;
use Drewlabs\Oauth\Clients\Exceptions\InvalidTokenSignatureException;
use Drewlabs\Oauth\Clients\Exceptions\TokenExpiresException;
use Drewlabs\Oauth\Clients\JwtTokenCredentials;

trait CreatesJwtClientCredentials
{
    use InteractsWithRequest;

    /**
     * Creates Jwt Token Credentials from request
     * 
     * @param mixed $request 
     * @param string $cookieName 
     * @return JwtTokenCredentials 
     * @throws InvalidTokenException 
     * @throws InvalidTokenSignatureException 
     * @throws TokenExpiresException 
     */
    public function jwtClientCredentialFromCookie($request, string $key, string $cookieName = 'jwt-cookie')
    {
        $jwtToken = $this->getRequestCookie($request, $cookieName);

        if (empty($jwtToken)) {
            return null;
        }
        return JwtTokenCredentials::new($key, (string)$jwtToken);
    }

    public function jwtClientFromAuthorizationHeader($request, string $key, $method = 'jwt')
    {
        $jwtToken = $this->getAuthorizationHeader($request, 'authorization', $method);
        // return a basic auth credential instance
        if (empty($jwtToken)) {
            return null;
        }
        return JwtTokenCredentials::new($key, (string)$jwtToken);
    }
}
