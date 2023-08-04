<?php

namespace Drewlabs\Laravel\Oauth\Clients\Tests\Stubs;

interface Callback
{
    public function __invoke(...$args);
}