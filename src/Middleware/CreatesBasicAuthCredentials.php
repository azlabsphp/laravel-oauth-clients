<?php

namespace Drewlabs\Laravel\Oauth\Middleware;

use Drewlabs\Oauth\Clients\BasicAuthCredentials;
use Drewlabs\Oauth\Clients\Contracts\CredentialsIdentityInterface;
use Drewlabs\Oauth\Clients\Exceptions\DecodeTokenException;
use Drewlabs\Oauth\Clients\Exceptions\MalformedBasicAuthException;

trait CreatesBasicAuthCredentials
{
    use InteractsWithRequest;

    /**
     * Creates basic auth credentials from request instance
     * 
     * @param \Illuminate\Http\Request $request 
     * @return null|CredentialsIdentityInterface 
     * @throws DecodeTokenException 
     * @throws MalformedBasicAuthException 
     */
    private function basicAuthClientCredentials($request): ?CredentialsIdentityInterface
    {
        $base64 = $this->getAuthorizationHeader($request, 'authorization', 'basic');
        if (null === $base64) {
            return null;
        }
        return BasicAuthCredentials::new($base64);
    }
}