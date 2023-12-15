<?php

namespace Drewlabs\Laravel\Oauth\Clients\Eloquent;

use Drewlabs\Laravel\Oauth\Clients\Contracts\AttributesAware;
use Drewlabs\Laravel\Oauth\Clients\Traits\Client as TraitsClient;
use Drewlabs\Query\Contracts\Queryable;
use Illuminate\Database\Eloquent\Model;

class Client extends Model implements Queryable, AttributesAware
{
    use TraitsClient;

    /**
     * The attributes that are mass assignable.
     *
     * @var array
     */
    protected $fillable = [
        'id',
        'name',
        'user_id',
        'ip_addresses',
        'secret',
        'redirect',
        'provider',
        'client_url',
        'expires_on',
        'personal_access_client',
        'password_client',
        'scopes',
        'revoked',
    ];

    /**
     * Associated table name
     *
     * @var string
     */
    protected $table = 'oauth_clients';

    /**
     * Associated table primary key
     *
     * @var string
     */
    protected $primaryKey = 'id';

    /**
     * List of relation for the current instance
     * 
     * @var array
     */
    private $relation_methods = [];

    public function getPrimaryKey()
    {
        return $this->primaryKey;
    }

    public function getDeclaredColumns()
    {
        return $this->getFillable();
    }

    public function getDeclaredRelations()
    {
        return $this->relation_methods ?? [];
    }

    protected static function boot()
    {
        parent::boot();
        static::saving(function(self $model) {
            $ip_addresses = $model->getAttributeFromArray('ip_addresses');
            if ($ip_addresses === '*' || is_null($ip_addresses)) {
                $model->ip_addresses = ['*'];
            }
        });
    }
}
