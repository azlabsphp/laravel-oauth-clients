<?php

namespace Drewlabs\Laravel\Oauth\Clients\Http;

use Drewlabs\Oauth\Clients\Contracts\AttributesAware as AbstractAttributesAware;

class AttributesAware implements AbstractAttributesAware
{
    /** @var array */
    private $attributes;

    /**
     * Creates attribute aware instance
     * 
     * @param array $attributes 
     */
    public function __construct(array $attributes = [])
    {
        $this->attributes = $attributes;
    }

    public function getAttribute(string $name)
    {
        return $this->attributes[$name] ?? null;
    }

    public function toArray()
    {
        return $this->attributes;
    }
}
