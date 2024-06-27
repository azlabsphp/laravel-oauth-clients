<?php

namespace Drewlabs\Laravel\Oauth\Clients\Middleware;

use Closure;
use Drewlabs\Laravel\Oauth\Clients\Contracts\RequestClientsProvider;
use Drewlabs\Laravel\Oauth\Clients\ServerRequest;
use Drewlabs\Oauth\Clients\Exceptions\AuthorizationException;
use InvalidArgumentException;

class BasicAuthClients
{
        
    /** @var RequestClientsProvider */
    private $clients;

    /**  @var ServerRequest */
    private $serverRequest;

    public function __construct(ServerRequest $serverRequest, RequestClientsProvider $clients)
    {
        $this->serverRequest = $serverRequest;
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
    public function handle($request, callable $next, ...$scopes)
    {
        try {
            if (is_null($client = $this->clients->getRequestClient($request))) {
                throw new AuthorizationException('basic auth client not found', 401);
            }
            $client->validate($scopes, $this->serverRequest->getRequestIp($request));
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
