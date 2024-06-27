<?php

declare(strict_types=1);

/*
 * This file is part of the drewlabs namespace.
 *
 * (c) Sidoine Azandrew <azandrewdevelopper@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Drewlabs\Laravel\Oauth\Clients\Middleware;

use Drewlabs\Laravel\Oauth\Clients\Contracts\RequestClientsProvider;
use Drewlabs\Oauth\Clients\Exceptions\AuthorizationException;

final class FirstPartyClients
{
    /** @var RequestClientsProvider */
    private $clients;

    /**
     * Create middleware class instance.
     */
    public function __construct(RequestClientsProvider $clients)
    {
        $this->clients = $clients;
    }

    /**
     * Handle an incoming request.
     *
     * @param mixed    $request
     * @param \Closure $next
     *
     * @throws \InvalidArgumentException
     * @throws AuthorizationException
     *
     * @return mixed
     */
    public function handle($request, callable $next)
    {
        try {
            if (null === ($client = $this->clients->getRequestClient($request))) {
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
