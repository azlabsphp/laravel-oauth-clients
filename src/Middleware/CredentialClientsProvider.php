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
use Drewlabs\Oauth\Clients\Contracts\CredentialsFactoryInterface;
use Drewlabs\Oauth\Clients\Contracts\CredentialsIdentityInterface;
use Drewlabs\Oauth\Clients\Contracts\VerifyClientSecretInterface;

class CredentialClientsProvider implements RequestClientsProvider
{
    /** @var CredentialsFactoryInterface */
    private $factory;

    /** @var ClientsRepository */
    private $repository;

    /** @var VerifyClientSecretInterface */
    private $secretVerifier;

    /**
     * Creates request client provider instance.
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
        if (null === ($credentials = $this->factory->create($request))) {
            return null;
        }

        return $this->getClientByCredentials($credentials);
    }

    public function getClientByCredentials(CredentialsIdentityInterface $credentials): ?ClientInterface
    {
        if (null === ($client = $this->repository->findById($credentials->getId()))) {
            return null;
        }

        if (!$this->secretVerifier->verify($client, $credentials->getSecret())) {
            return null;
        }

        return $client;
    }
}
