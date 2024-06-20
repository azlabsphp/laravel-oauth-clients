<?php

namespace Drewlabs\Laravel\Oauth\Clients;

use Drewlabs\Oauth\Clients\Contracts\AttributesAware;
use Drewlabs\Oauth\Clients\Contracts\PlainTextSecretAware;
use Drewlabs\Oauth\Clients\Contracts\ScopeInterface;
use JsonSerializable;
use Drewlabs\Oauth\Clients\Contracts\SecretClientInterface;

class Client implements PlainTextSecretAware, JsonSerializable, SecretClientInterface
{
    /**
     * @var AttributesAware
     */
    private $instance;

    /**
     * @var string|null
     */
    private $plainTextSecret;

    /**
     * Create client instance
     * 
     * @param AttributesAware $instance 
     * @param string|null $plainTextSecret 
     */
    public function __construct(AttributesAware $instance, string $plainTextSecret = null)
    {
        $this->instance = $instance;
        $this->plainTextSecret = $plainTextSecret;
    }

    public function isPasswordClient(): bool
    {
        return boolval($this->instance->getAttribute('password_client'));
    }

    public function isPersonalClient(): bool
    {
        return boolval($this->instance->getAttribute('personal_access_client'));
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
        return $this->plainTextSecret;
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
        return $this->instance->getAttribute('ip_addresses');
    }

    public function firstParty()
    {
        return $this->isPasswordClient() || $this->isPersonalClient();
    }

    public function isRevoked()
    {
        return boolval($this->instance->getAttribute('revoked'));
    }

    public function getScopes(): array
    {
        return (array)($this->instance->getAttribute('scopes'));
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

    public function __toArray()
    {
        $attributes = $this->instance->toArray();
        $attributes['personal_access_client'] = boolval($attributes['personal_access_client'] ?? false);
        $attributes['password_client'] = boolval($attributes['password_client'] ?? false);
        $attributes['revoked'] = $this->isRevoked();
        $attributes['ip_addresses'] = $this->getIpAddressesAttribute();
        $attributes['scopes'] = $this->getScopes();
        $plainTextSecret = $this->plainTextSecret;
        if (null === $plainTextSecret) {
            $plainTextSecret = sprintf("%s***", uniqid());
        }
        $attributes['plain_secret'] = $plainTextSecret;
        
        return $attributes;
    }
}
