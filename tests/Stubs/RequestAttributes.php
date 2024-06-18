<?php

namespace Drewlabs\Laravel\Oauth\Clients\Tests\Stubs;

class RequestAttributes
{
    /** @var array */
    private $attributes = [];


    public function add(array $values)
    {
        foreach ($values as $key => $value) {
            $this->attributes[$key] = $value;
        }
    }
}
