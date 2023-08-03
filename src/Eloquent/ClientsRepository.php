<?php

namespace Drewlabs\Laravel\Oauth\Clients\Eloquent;

use Drewlabs\Oauth\Clients\Contracts\ClientInterface;
use Closure;
use Drewlabs\Core\Helpers\Rand;
use Drewlabs\Laravel\Oauth\Clients\Client;
use Drewlabs\Oauth\Clients\Contracts\ClientsRepository as AbstractClientsRepository;
use Drewlabs\Oauth\Clients\Contracts\HashesClientSecret;
use Drewlabs\Oauth\Clients\Contracts\NewClientInterface;
use Drewlabs\Laravel\Oauth\Clients\Eloquent\Client as Model;
use Illuminate\Contracts\Database\Eloquent\Builder;

class ClientsRepository implements AbstractClientsRepository
{
    /**
     * @var HashesClientSecret
     */
    private $secretHasher;
    /**
     * @var int
     */
    private $keyLength;

    /**
     * @var Builder
     */
    private $builder;

    /**
     * Creates repository instance
     * 
     * @param Builder $builder 
     * @param HashesClientSecret $secretHasher 
     * @param int $keyLength 
     */
    public function __construct(Builder $builder, HashesClientSecret $secretHasher, int $keyLength = 32)
    {
        $this->builder = $builder;
        $this->secretHasher = $secretHasher;
        $this->keyLength = $keyLength ?? 32;
    }

    public function findByUserId($identifier): ClientInterface
    {
        /**
         * @var Model
         */
        $client = $this->builder->where('user_id', (string)$identifier)->first();
        return null === $client ? null : new Client($client);
    }

    public function findById($id): ClientInterface
    {
        /**
         * @var Model
         */
        $client = $this->builder->where('id', (string)$id)->first();
        return null === $client ? null : new Client($client);
    }

    public function updateById($id, NewClientInterface $attributes, ?Closure $callback = null)
    {
        $plainText = $attributes->getSecret();
        $hashedSecret = null;
        if (null !== $plainText) {
            $hashedSecret = $this->secretHasher->hashSecret($plainText);
        }

        $attributes = [
            'name' => $attributes->getName(),
            'user_id' => $attributes->getUserId(),
            'ip_addresses' => $attributes->getIpAddresses(),
            'secret' => $hashedSecret,
            'redirect' => $attributes->getRedirectUrl(),
            'provider' => $attributes->getProvider(),
            'client_url' => $attributes->getAppUrl(),
            'expires_on' => $attributes->getExpiresAt(),
            'personal_access_client' => $attributes->isPersonalClient(),
            'password_client' => $attributes->isPasswordClient(),
            'scopes' => $attributes->getScopes() ?? [],
            'revoked' => boolval($attributes->getRevoked()),
        ];

        // Remove null values from the attributes array
        $attributes = array_filter($attributes, function($attribute) {
            return null !== $attribute;
        });

        /**
         * @var Model
         */
        $client = $this->builder->create($attributes);

        $callback = $callback ?? function (ClientInterface $client) {
            return $client;
        };

        // Call the callback function on the new client instance
        return call_user_func_array($callback, [new Client($client, $plainText)]);
    }

    public function create(NewClientInterface $attributes, ?Closure $callback = null)
    {
        $plainText = $attributes->getSecret();
        if (null === $plainText) {
            $plainText = Rand::key($this->keyLength);
        }
        /**
         * @var Model
         */
        $client = $this->builder->create([
            'id' => $attributes->getId() ?? null,
            'name' => $attributes->getName(),
            'user_id' => $attributes->getUserId(),
            'ip_addresses' => $attributes->getIpAddresses(),
            'secret' => $this->secretHasher->hashSecret($plainText),
            'redirect' => $attributes->getRedirectUrl(),
            'provider' => $attributes->getProvider() ?? 'local',
            'client_url' => $attributes->getAppUrl(),
            'expires_on' => $attributes->getExpiresAt(),
            'personal_access_client' => $attributes->isPersonalClient(),
            'password_client' => $attributes->isPasswordClient(),
            'scopes' => $attributes->getScopes() ?? [],
            'revoked' => boolval($attributes->getRevoked()),
        ]);

        $callback = $callback ?? function (ClientInterface $client) {
            return $client;
        };

        // Call the callback function on the new client instance
        return call_user_func_array($callback, [new Client($client, $plainText)]);
    }

    public function deleteById($id, ?Closure $callback = null)
    {
        $result = $this->builder->where('id', $id)->delete();
        $callback = $callback ?? function ($value) {
            return $value;
        };
        return call_user_func_array($callback, [$result]);
    }
}
