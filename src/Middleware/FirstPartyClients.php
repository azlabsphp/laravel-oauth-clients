<?php

namespace Drewlabs\Laravel\Oauth\Clients\Middleware;

use Closure;
use Drewlabs\Laravel\Oauth\Clients\Contracts\RequestClientsProvider;
use Drewlabs\Oauth\Clients\Exceptions\AuthorizationException;
use InvalidArgumentException;

final class FirstPartyClients
{

    /** @var RequestClientsProvider */
    private $clients;

    /**
     * Create middleware class instance
     * 
     * @param RequestClientsProvider $clients 
     */
    public function __construct(RequestClientsProvider $clients)
    {
        $this->clients = $clients;
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
    public function handle($request, callable $next)
    {
        try {
            if (is_null($client = $this->clients->getRequestClient($request))) {
                throw new AuthorizationException('access client not found', 401);
            }
            // Case client does not have required privileges throw an authorization exception
            if (!$client->firstParty()) {
                throw new AuthorizationException('client does not have the required privileges');
            }

            // pass the server request through credentials validation layer
            if ($request->attributes) {
                // Added __X_REQUEST_CLIENT__ to request attributes
                $request->attributes->add(['__X_REQUEST_CLIENT__' => $client]);
            }
            // next request
            return $next($request);
        } catch (\Throwable $e) {
            throw new AuthorizationException($e->getMessage(), 401);
        }
    }
}
