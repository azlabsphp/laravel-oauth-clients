<?php

namespace Drewlabs\Laravel\Oauth\Middleware;

use Drewlabs\Oauth\Clients\Contracts\CredentialsIdentityInterface;
use Drewlabs\Oauth\Clients\Credentials;
use Drewlabs\Oauth\Clients\Exceptions\AuthorizationException;

trait CreatesClientCredentials
{
    use InteractsWithRequest;

    /**
     * Creates client credentials from request cookie
     * 
     * @param \Illuminate\Http\Request $request 
     * @return null|CredentialsIdentityInterface 
     */
    private function fromCookie($request): ?CredentialsIdentityInterface
    {

        // query for clientid cookie value
        if ((null === $clientId = $this->getRequestCookie($request, 'clientid'))) {
            return null;
        }

        // query for clientsecret cookie value
        if ((null === $clientSecret = $this->getRequestCookie($request, 'clientsecret'))) {
            return null;
        }

        return new Credentials($clientId, $clientSecret);
    }

    /**
     * Create client credentials from server request
     * 
     * @param \Illuminate\Http\Request $request 
     * @return null|CredentialsIdentityInterface 
     */
    private function fromHeaders($request): ?CredentialsIdentityInterface
    {
        // query for client secret header value
        if (null === ($secret = $this->getClientSecret($request))) {
            throw new AuthorizationException('client secret header value not found');
        }

        // query fir client id header value
        if (null === ($client = $this->getClientId($request))) {
            throw new AuthorizationException('client id header value not found');
        }

        return new Credentials((string)$client, (string)$secret);
    }

    /**
     * Get client secret from server request
     * 
     * @param \Illuminate\Http\Request $request
     * 
     * @return null|string 
     */
    private function getClientSecret($request)
    {
        // We search for authorization secret using all possible header values
        // in order to support legacy applications
        $secret = $this->getHeader($request, 'x-client-secret', null);
        $secret = $secret ?? $this->getHeader($request, 'x-authorization-client-secret', null);
        $secret = $secret ?? $this->getHeader($request, 'x-authorization-client-token', null);

        if (null !== $secret) {
            return $secret;
        }

        return $request->input('client_secret');
    }

    /**
     * Get client id from server request
     * 
     * @param \Illuminate\Http\Request $request
     * 
     * @return null|string 
     */
    private function getClientId($request)
    {
        
        // We search for authorization secret using all possible header values
        // in order to support legacy applications
        $secret = $this->getHeader($request, 'x-authorization-client-id', null);
        $secret = $secret ?? $this->getHeader($request, 'x-client-id', null);
        $secret = $secret ?? $this->getHeader($request, 'x-authorization-client-token', null);

        if (null !== $secret) {
            return $secret;
        }

        return $request->input('client_id');
    }
}
