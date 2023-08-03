<?php

namespace Drewlabs\Laravel\Oauth\Clients\Traits;

use DateTimeImmutable;
use Drewlabs\Core\Helpers\Str;
use Drewlabs\Core\Helpers\UUID;

trait Client
{

    public function getName()
    {
        return $this->getAttribute('name');
    }

    /**
     * Determine if the client is a confidential client.
     *
     * @return bool
     */
    public function confidential()
    {
        return !empty($this->secret);
    }

    public function getScopesAttribute()
    {
        $scopes = $this->getAttributeFromArray('scopes') ?? ['*'];
        return Str::isStr($scopes) ? Str::split($scopes, ',') : $scopes;
    }

    public function setScopesAttribute($value)
    {
        $scopes = $value ?? ['*'];
        $this->attributes['scopes'] = Str::isStr($scopes) ? $scopes : implode(',', $scopes);
    }

    /**
     * Get the casts array.
     *
     * @return array
     */
    public function getCasts()
    {
        $casts = [
            'grant_types' => 'array',
            'personal_access_client' => 'bool',
            'password_client' => 'bool',
            'revoked' => 'bool',
        ];

        if ($this->getIncrementing()) {
            return array_merge([$this->getKeyName() => $this->getKeyType()], $casts);
        }

        return $casts;
    }

    public function setIpAddressesAttribute($value)
    {
        $this->attributes['ip_addresses'] = is_array($value) ? Str::join($value, ',') : (null === $value ? '*' : $value);
    }

    public function setClientIpAttribute($value)
    {
        $this->setIpAddressesAttribute($value);
    }

    public function getIpAddressesAttribute()
    {
        return array_filter(Str::split($this->getAttributeFromArray('ip_addresses') ?? '*', ','), function ($current) {
            return !empty($current);
        });
    }

    /**
     * Get the auto-incrementing key type.
     *
     * @return string
     */
    public function getKeyType()
    {
        return 'string';
    }

    /**
     * Get the value indicating whether the IDs are incrementing.
     *
     * @return bool
     */
    public function getIncrementing()
    {
        return false;
    }

    /**
     * Checks is the client is a first party client
     *
     * @return bool
     */
    public function firstParty()
    {
        return boolval($this->personal_access_client) || boolval($this->password_client);
    }

    public function getSecretAttribute()
    {
        return $this->getAttributeFromArray('secret');
    }


    public function isRevoked()
    {
        return boolval($this->getAttributeFromArray('revoked'));
    }

    public function getScopes()
    {
        return $this->getScopesAttribute();
    }

    public function hasScope($scope)
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

    /**
     * @return array
     */
    public function getHidden()
    {
        return ['secret'];
    }

    /**
     * @return array 
     */
    public function getAppends()
    {
        return array_merge($this->appends ?? []);
    }

    /**
     * @return array 
     */
    public function getArrayableAppends()
    {
        try {
            return array_merge(parent::getArrayableAppends() ?? [], $this->getAppends());
        } catch (\Throwable $e) {
            return $this->getAppends();
        }
    }

    public function getUserId()
    {
        return $this->user_id;
    }

    public static function boot()
    {
        parent::boot();
        static::creating(function (self $model) {
            $schemaBuilder = $model->getConnection()->getSchemaBuilder();
            if (null === $model->{$model->getPrimaryKey()}) {
                $model->{$model->getPrimaryKey()} = UUID::ordered();
            }
            if ($schemaBuilder->hasColumn($model->getTable(), 'ip_addresses')) {
                $model->setIpAddressesAttribute($model->ip_addresses);
            }
            if (null !== ($date = $model->expires_on)) {
                $model->expires_on = static::formatExpiresOn($date, $model->getDateFormat());
            }
            if ($schemaBuilder->hasColumn($model->getTable(), 'scopes')) {
                $scopes = empty($value = $model->getAttributeFromArray('scopes')) ? [] : $value;
                if (is_array($scopes)) {
                    $model->scopes = Str::join($model->scopes, ',');
                }
            }
            $model->cleanupAttributes();
        });

        static::updating(function (self $model) {
            $schemaBuilder = $model->getConnection()->getSchemaBuilder();
            if ($schemaBuilder->hasColumn($model->getTable(), 'ip_addresses')) {
                $model->setIpAddressesAttribute($model->ip_addresses);
            }
            if (null !== ($date = $model->expires_on)) {
                $model->expires_on = static::formatExpiresOn($date, $model->getDateFormat());
            }
            if ($schemaBuilder->hasColumn($model->getTable(), 'scopes')) {
                if (is_array($model->scopes)) {
                    $model->scopes = Str::join($model->scopes, ',');
                }
            }
            $model->cleanupAttributes();
        });
    }

    /**
     *
     * @param string|\DateTimeInterface|null $date
     * @param string $format
     * @return string
     */
    private static function formatExpiresOn($date, $format = 'Y-m-d H:i:s')
    {
        return $date instanceof \DateTimeInterface ? $date->format($format) : (new DateTimeImmutable())->setTimestamp(strtotime($date))->format($format);
    }

    private function cleanupAttributes()
    {
        $schemaBuilder = $this->getConnection()->getSchemaBuilder();
        if ($schemaBuilder->hasColumn($this->getTable(), 'revoked')) {
            $this->setAttribute('revoked', $this->revoked ?? false);
        } else {
            unset($this->attributes['revoked']);
        }

        // We unset the columns that may possibly not be present on the application
        // database table due to partial database table definition in previous releases
        $this->unsetMissingColumns($this->getTable(), ['name', 'user_id', 'redirect', 'provider', 'client_url']);
    }

    private function unsetMissingColumns(string $table, array $columns)
    {
        $schemaBuilder = $this->getConnection()->getSchemaBuilder();
        foreach ($columns as $column) {
            if (!$schemaBuilder->hasColumn($table, $column)) {
                unset($this->attributes[$column]);
            }
        }
    }
}
