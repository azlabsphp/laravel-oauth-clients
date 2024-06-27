<?php

namespace Drewlabs\Laravel\Oauth\Clients;

class Middlewares
{
    /**
     * returns a list `clients, clients.jwt, clients.basic, clients.*` of default middleware that can be added to laravel application
     * 
     * @return array
     */
    public static function useDefaults()
    {
        return [
            'clients' => \Drewlabs\Laravel\Oauth\Clients\Middleware\Clients::class,
            'clients.jwt' => \Drewlabs\Laravel\Oauth\Clients\Middleware\JwtAuthClients::class,
            'clients.basic' => \Drewlabs\Laravel\Oauth\Clients\Middleware\BasicAuthClients::class,
            'clients.*' => \Drewlabs\Laravel\Oauth\Clients\Middleware\FirstPartyClients::class
        ];
    }
}