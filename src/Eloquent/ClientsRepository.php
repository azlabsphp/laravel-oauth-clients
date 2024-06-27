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

use Drewlabs\Core\Helpers\UUID;
use Drewlabs\Laravel\Oauth\Clients\Client;
use Drewlabs\Laravel\Oauth\Clients\Contracts\ClientsRepository as AbstractClientsRepository;
use Drewlabs\Laravel\Oauth\Clients\Eloquent\Client as Model;
use Drewlabs\Oauth\Clients\Contracts\ClientInterface;
use Drewlabs\Oauth\Clients\Contracts\HashesClientSecret;
use Drewlabs\Oauth\Clients\Contracts\NewClientInterface;
use Illuminate\Contracts\Database\Eloquent\Builder;

class ClientsRepository implements AbstractClientsRepository
{
    /** @var HashesClientSecret */
    private $secretHasher;

    /** @var int|callable */
    private $keyLength;

    /** @var Builder */
    private $builder;

    /** @var string */
    private $apiKeyPrefix;

    /**
     * Creates repository instance.
     *
     * @param int|callable $keyLength
     */
    public function __construct(Builder $builder, HashesClientSecret $secretHasher, $keyLength = 32, string $apiKeyPrefix = null)
    {
        $this->builder = $builder;
        $this->secretHasher = $secretHasher;
        $this->apiKeyPrefix = $apiKeyPrefix ?: '';
        $this->keyLength = \is_int($keyLength) ? max($keyLength, 32) : ($keyLength ?? 32);
    }

    public function findByApiKey(string $key): ?ClientInterface
    {

        /** @var Model */
        $client = $this->builder->where('api_key', $key)->first();

        return null === $client ? null : new Client($client);
    }

    public function findByUserId($identifier): array
    {
        return $this->builder->where('user_id', (string) $identifier)->get()->map(static function ($client) {
            return new Client($client);
        })->all();
    }

    public function findById($id): ?ClientInterface
    {
        /** @var Model */
        $client = $this->builder->where('id', (string) $id)->first();

        return null === $client ? null : new Client($client);
    }

    public function updateById($id, NewClientInterface $attributes, \Closure $callback = null)
    {
        $plainText = $attributes->getSecret();
        $hashedSecret = null;
        if (null !== $plainText) {
            $hashedSecret = $this->secretHasher->hashSecret($plainText);
        }
        $ipAddresses = $attributes->getIpAddresses();
        $scopes = $attributes->getScopes();

        $attributes = [
            'name' => $attributes->getName(),
            'user_id' => $attributes->getUserId(),
            'ip_addresses' => \is_array($ipAddresses) ? implode(',', $ipAddresses) : ($ipAddresses ?? '*'),
            'secret' => $hashedSecret,
            'redirect' => $attributes->getRedirectUrl(),
            'provider' => $attributes->getProvider(),
            'client_url' => $attributes->getAppUrl(),
            'expires_on' => (null !== $expiresAt = $attributes->getExpiresAt()) ? $this->formatExpiresOn($expiresAt) : $expiresAt,
            'personal_access_client' => $attributes->isPersonalClient(),
            'password_client' => $attributes->isPasswordClient(),
            'scopes' => \is_array($scopes) ? implode(',', $scopes) : ($scopes ?? []),
            'revoked' => $attributes->getRevoked(),
            'api_key' => $plainText,
        ];

        // Remove null values from the attributes array
        $attributes = array_filter($attributes, static function ($attribute) {
            return null !== $attribute;
        });

        // Update the client with provided attributes
        $this->builder->where('id', $id)->update($attributes);

        // Query for client if the result of the update query is not 0
        $client = $this->builder->where('id', (string) $id)->first();

        $callback = $callback ?? static function (ClientInterface $client = null) {
            return $client;
        };

        // Call the callback function on the new client instance
        return \call_user_func_array($callback, [null === $client ? null : new Client($client, $plainText)]);
    }

    public function create(NewClientInterface $attributes, \Closure $callback = null)
    {
        $plainText = $attributes->getSecret();
        $plainText = $plainText ?? $this->createSecret();
        $ipAddresses = $attributes->getIpAddresses();
        $scopes = $attributes->getScopes();

        /** @var Model */
        $client = $this->builder->create([
            'id' => $attributes->getId() ?? UUID::ordered(),
            'name' => $attributes->getName(),
            'user_id' => $attributes->getUserId(),
            'ip_addresses' => \is_array($ipAddresses) ? implode(',', $ipAddresses) : ($ipAddresses ?? '*'),
            'secret' => $this->secretHasher->hashSecret($plainText),
            'redirect' => $attributes->getRedirectUrl(),
            'provider' => $attributes->getProvider() ?? 'local',
            'client_url' => $attributes->getAppUrl(),
            'expires_on' => (null !== $expiresAt = $attributes->getExpiresAt()) ? $this->formatExpiresOn($expiresAt) : $expiresAt,
            'personal_access_client' => $attributes->isPersonalClient(),
            'password_client' => $attributes->isPasswordClient(),
            'scopes' => \is_array($scopes) ? implode(',', $scopes) : ($scopes ?? []),
            'revoked' => (bool) $attributes->getRevoked(),
            'api_key' => $plainText,
        ]);

        $callback = $callback ?? static function (ClientInterface $client) {
            return $client;
        };

        // Call the callback function on the new client instance
        return \call_user_func_array($callback, [new Client($client, $plainText)]);
    }

    public function deleteById($id, \Closure $callback = null)
    {
        $result = $this->builder->where('id', $id)->delete();
        $callback = $callback ?? static function ($value) {
            return $value;
        };

        return \call_user_func_array($callback, [$result]);
    }

    /**
     * Create client secret key.
     *
     * @return string
     */
    private function createSecret()
    {
        if (\is_int($this->keyLength)) {
            printf('Key lenght is int: %d', $this->keyLength);

            return str_replace('.', '', sprintf('%s_%s', $this->apiKeyPrefix, base64_encode(bin2hex(random_bytes((int) ($this->keyLength / 2))))));
        }
        $key = \call_user_func($this->keyLength);

        if (!\is_string($key)) {
            throw new \RuntimeException('Key generator must return a valid PHP string');
        }

        return $key;
    }

    /**
     * @param string|\DateTimeInterface|null $date
     * @param string                         $format
     *
     * @return string
     */
    private function formatExpiresOn($date, $format = 'Y-m-d H:i:s')
    {
        return $date instanceof \DateTimeInterface ? $date->format($format) : (new \DateTimeImmutable())->setTimestamp(strtotime($date))->format($format);
    }
}
