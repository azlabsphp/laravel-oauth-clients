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
use Drewlabs\Oauth\Clients\Contracts\ClientInterface;

class ClientsProvider implements RequestClientsProvider
{
    /** @var RequestClientsProvider */
    private $providers;

    /**
     * Creates request client provider instance.
     *
     * @param RequestClientsProvider[] $providers
     */
    public function __construct(...$providers)
    {
        $this->providers = $providers;
    }

    public function getRequestClient($request): ?ClientInterface
    {
        /** @var ClientInterface|null $client */
        $client = null;
        foreach ($this->providers as $provider) {
            $client = $provider->getRequestClient($request);
            if (null !== $client) {
                break;
            }
        }

        return $client;
    }
}
