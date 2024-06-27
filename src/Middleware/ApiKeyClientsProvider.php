<?php

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
     * Creates request client provider instance
     * 
     * @param ClientsRepository $repository 
     * @param CredentialsFactoryInterface $factory 
     * @param VerifyClientSecretInterface $secretVerifier 
     */
    public function __construct(ServerRequestFacade $requestAdapter, ClientsRepository $repository)
    {
        $this->repository = $repository;
        $this->requestAdapter = $requestAdapter;
    }

    public function getRequestClient($request): ?ClientInterface
    {
        if (is_null($apiAccessToken = $this->getApiAccessToken($request))) {
            return null;
        }
        return $this->repository->findByApiKey($apiAccessToken); 
    }


    /**
     * Query api acess token from request headers
     * 
     * @param mixed $request 
     * @return string|null 
     */
    private function getApiAccessToken($request)
    {
        /** @var string */
        $accessToken = null;
        if (is_null($accessToken = $this->requestAdapter->getAuthorizationHeader($request, 'access_token'))) {
            $accessToken = $this->requestAdapter->getAuthorizationHeader($request, 'api_key');
        }
        return $accessToken;
    }
}
