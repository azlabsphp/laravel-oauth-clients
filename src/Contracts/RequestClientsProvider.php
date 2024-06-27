<?php

namespace Drewlabs\Laravel\Oauth\Clients\Contracts;

use Drewlabs\Oauth\Clients\Contracts\ClientInterface;

interface RequestClientsProvider
{

    /**
     * Find the request client instance based on request attributes, header, and inputs
     * 
     * @param mixed $request 
     * @return null|ClientInterface 
     */
    public function getRequestClient($request): ?ClientInterface;
}