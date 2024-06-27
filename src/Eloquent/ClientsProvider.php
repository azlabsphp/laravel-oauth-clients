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

namespace Drewlabs\Laravel\Oauth\Clients\Eloquent;

use Drewlabs\Oauth\Clients\Contracts\ClientInterface;
use Drewlabs\Oauth\Clients\Contracts\ClientProviderInterface;
use Drewlabs\Oauth\Clients\Contracts\CredentialsIdentityInterface;
use Drewlabs\Oauth\Clients\Contracts\VerifyClientSecretInterface;

/**
 * @deprecated
 */
class ClientsProvider implements ClientProviderInterface
{
    /**
     * @var ClientsRepository
     */
    private $repository;

    /**
     * @var VerifyClientSecretInterface
     */
    private $secretVerifier;

    /**
     * Creates class instance.
     */
    public function __construct(ClientsRepository $repository, VerifyClientSecretInterface $secretVerifier)
    {
        $this->repository = $repository;
        $this->secretVerifier = $secretVerifier;
    }

    public function __invoke(CredentialsIdentityInterface $credentials): ?ClientInterface
    {
        return $this->findByCredentials($credentials);
    }

    public function findByCredentials(CredentialsIdentityInterface $credentials): ?ClientInterface
    {
        $client = $this->repository->findById($credentials->getId());

        if (null === $client) {
            return null;
        }

        if (false === $this->secretVerifier->verify($client, $credentials->getSecret())) {
            return null;
        }

        return $client;
    }
}
