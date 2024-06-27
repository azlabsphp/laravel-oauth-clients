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

namespace Drewlabs\Laravel\Oauth\Clients;

use Drewlabs\Oauth\Clients\Contracts\ApiKeyAware;
use Drewlabs\Oauth\Clients\Contracts\AttributesAware;
use Drewlabs\Oauth\Clients\Contracts\PlainTextSecretAware;
use Drewlabs\Oauth\Clients\Contracts\ScopeInterface;
use Drewlabs\Oauth\Clients\Contracts\SecretClientInterface;
use Drewlabs\Oauth\Clients\Exceptions\AuthorizationException;
use Drewlabs\Oauth\Clients\Exceptions\MissingScopesException;

class Client implements PlainTextSecretAware, \JsonSerializable, SecretClientInterface, ApiKeyAware
{
    /** @var AttributesAware */
    private $instance;

    /** @var string|null */
    private $plainTextSecret;

    /**
     * Create client instance.
     */
    public function __construct(AttributesAware $instance, string $plainTextSecret = null)
    {
        $this->instance = $instance;
        $this->plainTextSecret = $plainTextSecret;
    }

    public function __toArray()
    {
        $attributes = $this->instance->toArray();
        $attributes['personal_access_client'] = (bool) ($attributes['personal_access_client'] ?? false);
        $attributes['password_client'] = (bool) ($attributes['password_client'] ?? false);
        $attributes['revoked'] = $this->isRevoked();
        $attributes['ip_addresses'] = $this->getIpAddresses();
        $attributes['scopes'] = $this->getScopes();
        $plainTextSecret = $this->plainTextSecret;
        if (null === $plainTextSecret) {
            $plainTextSecret = sprintf('%s***', uniqid());
        }
        $attributes['plain_secret'] = $plainTextSecret;
        $attributes['api_key'] = $this->getApiKey();

        return $attributes;
    }

    public function getPlainTextSecret(): ?string
    {
        return $this->plainTextSecret;
    }

    public function getIpAddresses(): array
    {
        return $this->instance->getAttribute('ip_addresses');
    }

    public function validate(array $scopes = [], string $ip = null): bool
    {

        // Case the client is revoked, we throw an authorization exception
        if ($this->isRevoked()) {
            throw new AuthorizationException('client has been revoked');
        }

        // Case client does not have the required scopes we throw a Missing scope exception
        if (!$this->hasScope($scopes)) {
            $scopes = $scopes instanceof ScopeInterface ? (string) $scopes : $scopes;
            $scopes = \is_string($scopes) ? [$scopes] : $scopes;
            throw new MissingScopesException($this->getKey(), array_diff($this->getScopes(), $scopes));
        }

        // Case the client is a first party client, we do not check for
        // ip address as first party clients are intended to have administration privilege
        // and should not be used by third party applications
        if ($this->firstParty()) {
            return true;
        }

        // Provide the client request headers in the proxy request headers definition Get Client IP Addresses
        $ips = null !== ($ips = $this->getIpAddresses()) ? $ips : [];

        // Check whether * exists in the list of client ips
        if (!\in_array('*', $ips, true) && (null !== $ip)) {
            // // Return the closure handler for the next middleware
            // Get the request IP address
            if (!\in_array($ip, $ips, true)) {
                throw new AuthorizationException(sprintf('unauthorized request origin %s', \is_array($ip) ? implode(',', $ip) : $ip));
            }
        }

        return true;
    }

    public function getApiKey(): ?string
    {
        return $this->instance->getAttribute('api_key');
    }

    public function isPasswordClient(): bool
    {
        return (bool) $this->instance->getAttribute('password_client');
    }

    public function isPersonalClient(): bool
    {
        return (bool) $this->instance->getAttribute('personal_access_client');
    }

    public function isConfidential(): bool
    {
        return !empty($this->instance->getAttribute('secret'));
    }

    public function getHashedSecret()
    {
        return $this->instance->getAttribute('secret');
    }

    public function getPlainSecretAttribute()
    {
        return $this->getPlainTextSecret();
    }

    public function getKey()
    {
        return $this->instance->getAttribute('id');
    }

    public function getName(): ?string
    {
        return $this->instance->getAttribute('name');
    }

    public function getUserId()
    {
        return $this->instance->getAttribute('user_id');
    }

    public function getIpAddressesAttribute()
    {
        return $this->getIpAddresses();
    }

    public function firstParty()
    {
        return $this->isPasswordClient() || $this->isPersonalClient();
    }

    public function isRevoked()
    {
        return (bool) $this->instance->getAttribute('revoked');
    }

    public function getScopes(): array
    {
        return (array) $this->instance->getAttribute('scopes');
    }

    public function hasScope($scope): bool
    {
        $clientScopes = $this->getScopes() ?? ['*'];
        if (\in_array('*', $clientScopes, true)) {
            return true;
        }
        if (empty($scope)) {
            return true;
        }
        if ($scope instanceof ScopeInterface) {
            $scope = (string) $scope;
        }

        return !empty(array_intersect(\is_string($scope) ? [$scope] : $scope, $clientScopes ?? []));
    }

    public function getExpiresAt()
    {
        return $this->instance->getAttribute('expires_on');
    }

    #[\ReturnTypeWillChange]
    public function jsonSerialize()
    {
        return $this->__toArray();
    }
}
