<?php

namespace Drewlabs\Laravel\Oauth\Clients\Middleware;

use Drewlabs\Oauth\Clients\Contracts\ClientInterface;
use Drewlabs\Laravel\Oauth\Clients\Contracts\RequestClientsProvider;

class ClientsProvider implements RequestClientsProvider
{

    /** @var RequestClientsProvider */
    private $providers;

    /**
     * Creates request client provider instance
     * 
     * @param RequestClientsProvider[] $providers
     */
    public function __construct(...$providers) {
        $this->providers = $providers;
    }


    public function getRequestClient($request): ?ClientInterface
    {
        /** @var null|ClientInterface $client */
        $client = null;
        foreach ($this->providers as $provider) {
            $client = $provider->getRequestClient($request);
            if (!is_null($client)) {
                break;
            }
        }
        return $client;
    }
}
