<?php

namespace Drewlabs\Laravel\Oauth\Clients\Tests\Stubs;

interface HeadersBag
{
    public function get(string $name);

    public function all(): array;
}