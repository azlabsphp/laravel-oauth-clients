<?php

namespace Drewlabs\Laravel\Oauth\Clients\Tests\Stubs;

class Request
{
    /**
     * @var array
     */
    private $ips = [];

    /**
     * 
     * @var HeadersBag
     */
    public $headers;

    /**
     * @var HeadersBag
     */
    public $cookies;

    /**
     * @var array
     */
    private $inputs = [];

    /** @var RequestAttributes */
    public $attributes;

    /**
     * Create class instance
     * 
     * @param mixed $headers 
     * @param mixed $cookies 
     * @param array $ips 
     */
    public function __construct($headers, $cookies = null, array $ips = [], array $inputs = [])
    {
        $this->ips = $ips ?? [];
        $this->headers = $headers;
        $this->cookies = $cookies;
        $this->inputs = $inputs ?? [];
        $this->attributes = new RequestAttributes;

    }

    public function ips()
    {
        return $this->ips;
    }

    public function input(string $name, $default = null)
    {
        return $this->inputs[$name] ?? $default;
    }
}