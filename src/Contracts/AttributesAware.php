<?php

namespace Drewlabs\Laravel\Oauth\Clients\Contracts;

interface AttributesAware
{
    /**
     * Returns the value of `$name` attribute or property
     * 
     * @param string $name 
     * @return mixed 
     */
    public function getAttribute(string $name);

    /**
     * Returns array representation of the current instance
     * 
     * @return array 
     */
    public function toArray();
}