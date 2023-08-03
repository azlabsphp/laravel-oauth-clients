<?php

namespace Drewlabs\Laravel\Oauth\Clients;

use Drewlabs\Laravel\Oauth\Clients\Contracts\AttributesAware;
use Drewlabs\Oauth\Clients\Contracts\PlainTextSecretAware;
use JsonSerializable;
use Drewlabs\Oauth\Clients\Contracts\SecretClientInterface;

class Client implements PlainTextSecretAware, JsonSerializable, SecretClientInterface
{
    /**
     * @var AttributesAware
     */
    private $model;

    /**
     * @var string|null
     */
    private $plainTextSecret;

    /**
     * Create client instance
     * 
     * @param AttributesAware $model 
     * @param string|null $plainTextSecret 
     */
    public function __construct(AttributesAware $model, string $plainTextSecret = null)
    {
        $this->model = $model;
        $this->plainTextSecret = $plainTextSecret;
    }

    public function getHashedSecret()
    {
        return $this->model->getAttribute('secret');
    }

    public function getPlainSecretAttribute()
    {
        return $this->plainTextSecret;
    }

    public function getKey()
    {
        return $this->model->getAttribute('id');
    }

    public function getName(): ?string
    {
        return $this->model->getAttribute('name');
    }

    public function getUserId()
    {
        return $this->model->getAttribute('user_id');
    }

    public function getIpAddressesAttribute()
    {
        return $this->model->getAttribute('ip_addresses');
    }

    public function firstParty()
    {
        return boolval($this->model->getAttribute('personal_access_client')) || boolval($this->model->getAttribute('password_client'));
    }

    public function isRevoked()
    {
        return boolval($this->model->getAttribute('revoked'));
    }

    public function getScopes(): array
    {
        return (array)($this->model->getAttribute('scopes'));
    }

    public function hasScope($scope): bool
    {
        $clientScopes = $this->getScopes() ?? ['*'];

        if (in_array('*', $clientScopes)) {
            return true;
        }

        if (empty($scope)) {
            return true;
        }

        $scope = (string)$scope;

        return !empty(array_intersect(is_string($scope) ? [$scope] : $scope, $clientScopes ?? []));
    }

    #[\ReturnTypeWillChange]
    public function jsonSerialize()
    {
        return $this->__toArray();
    }

    public function __toArray()
    {
        $attributes = $this->model->toArray();
        $plainTextSecret = $this->plainTextSecret;
        if (null === $plainTextSecret) {
            $plainTextSecret = sprintf("%s***", uniqid());
        }
        $attributes['client_secret'] = $plainTextSecret;
    }
}
