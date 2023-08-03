<?php

namespace Drewlabs\Laravel\Oauth\Clients\Tests\Stubs;

use Drewlabs\Oauth\Clients\NewClient;

class NewClientFactory
{
    /**
     * Creates new client instance
     * 
     * @param mixed $id 
     * @param string $name
     * @param bool $personal 
     * @param bool $password 
     * @return NewClient 
     */
    public function create($id = null, string $name = null, string $secret = null, bool $personal = null, bool $password = null)
    {
        return (new NewClient($id, $personal, $password))->setName($name)->setSecret($secret);
    }
}