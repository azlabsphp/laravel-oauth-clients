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

use Drewlabs\Laravel\Oauth\Clients\Contracts\ClientsRepository;
use Drewlabs\Laravel\Oauth\Clients\Contracts\RequestClientsProvider;
use Drewlabs\Oauth\Clients\Contracts\ClientInterface;
use Drewlabs\Oauth\Clients\Contracts\ServerRequestFacade;

class ApiKeyClientsProvider implements RequestClientsProvider
{
    /** @var ClientsRepository */
    private $repository;

    /** @var ServerRequestFacade */
    private $requestAdapter;

    /**
     * Creates request client provider instance.
     */
    public function __construct(ServerRequestFacade $requestAdapter, ClientsRepository $repository)
    {
        $this->repository = $repository;
        $this->requestAdapter = $requestAdapter;
    }

    public function getRequestClient($request): ?ClientInterface
    {
        if (null === ($apiAccessToken = $this->getApiAccessToken($request))) {
            return null;
        }

        return $this->repository->findByApiKey($apiAccessToken);
    }

    /**
     * Query api acess token from request headers.
     *
     * @param mixed $request
     *
     * @return string|null
     */
    private function getApiAccessToken($request)
    {
        /** @var string */
        $accessToken = null;
        if (null === ($accessToken = $this->requestAdapter->getAuthorizationHeader($request, 'access_token'))) {
            $accessToken = $this->requestAdapter->getAuthorizationHeader($request, 'api_key');
        }

        return $accessToken;
    }
}
