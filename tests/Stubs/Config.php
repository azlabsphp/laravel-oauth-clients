<?php

namespace Drewlabs\Laravel\Oauth\Clients\Tests\Stubs;

use Drewlabs\Core\Helpers\Arr;
use Illuminate\Contracts\Config\Repository;

class Config implements Repository
{
    /**
     * @var array
     */
    private $values;

    /**
     * Creates a configuration object instance
     * 
     * @return void 
     */
    public function __construct()
    {
        $this->values = [];
    }

    public function has($key)
    {
        return null !== $this->get($key, null);
    }

    public function get($key, $default = null)
    {
        return Arr::get($this->values, $key, $default);
    }

    public function all()
    {
        return $this->values;
    }

    public function set($key, $value = null)
    {
        Arr::set($this->values, $key, $value);
    }

    public function prepend($key, $value)
    {
        // 
    }

    public function push($key, $value)
    {
        //
    }
}
