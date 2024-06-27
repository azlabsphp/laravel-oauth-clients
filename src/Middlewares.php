<?php

declare(strict_types=1);

/*
 * This file is part of the drewlabs namespace.
 *
 * (c) Sidoine Azandrew <azandrewdevelopper@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Drewlabs\Laravel\Oauth\Clients;

class Middlewares
{
    /**
     * returns a list `clients, clients.jwt, clients.basic, clients.*` of default middleware that can be added to laravel application.
     *
     * @return array
     */
    public static function useDefaults()
    {
        return [
            'clients' => Middleware\Clients::class,
            'clients.jwt' => Middleware\JwtAuthClients::class,
            'clients.basic' => Middleware\BasicAuthClients::class,
            'clients.*' => Middleware\FirstPartyClients::class,
        ];
    }
}
