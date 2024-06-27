<?php

namespace Drewlabs\Laravel\Oauth\Clients\Middleware;

use Drewlabs\Laravel\Oauth\Clients\Contracts\ClientsRepository;
use Drewlabs\Laravel\Oauth\Clients\Contracts\RequestClientsProvider;
use Drewlabs\Oauth\Clients\Contracts\CredentialsFactoryInterface;
use Drewlabs\Oauth\Clients\Contracts\VerifyClientSecretInterface;
use Drewlabs\Oauth\Clients\Contracts\CredentialsIdentityInterface;
use Drewlabs\Oauth\Clients\Contracts\ClientInterface;

class CredentialClientsProvider implements RequestClientsProvider
{

    /** @var CredentialsFactoryInterface */
    private $factory;

    /** @var ClientsRepository */
    private $repository;

    /** @var VerifyClientSecretInterface */
    private $secretVerifier;

    /**
     * Creates request client provider instance
     * 
     * @param ClientsRepository $repository 
     * @param CredentialsFactoryInterface $factory 
     * @param VerifyClientSecretInterface $secretVerifier 
     */
    public function __construct(CredentialsFactoryInterface $factory, VerifyClientSecretInterface $secretVerifier, ClientsRepository $repository)
    {
        $this->repository = $repository;
        $this->secretVerifier = $secretVerifier;
        $this->factory = $factory;
    }


    public function getRequestClient($request): ?ClientInterface
    {
        /** @var CredentialsIdentityInterface $credentials */
        if (is_null($credentials = $this->factory->create($request))) {
            return null;
        }
        return $this->getClientByCredentials($credentials);
    }


    public function getClientByCredentials(CredentialsIdentityInterface $credentials): ?ClientInterface
    {
        if (is_null($client = $this->repository->findById($credentials->getId()))) {
            return null;
        }

        if (!$this->secretVerifier->verify($client, $credentials->getSecret())) {
            return null;
        }

        return $client;
    }
}
