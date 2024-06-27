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

use Drewlabs\Laravel\Oauth\Clients\Eloquent\Client;

return [
    'clients' => [
        'model' => Client::class,
        'hash' => true,
    ],

    'credentials' => [
        'jwt' => [
            'cookie' => env('JWT_CREDENTIALS_COOKIE_NAME', 'jwt-cookie'),
            'header' => env('JWT_CREDENTIALS_HEADER_NAME', 'jwt'),
            'key' => env('APP_KEY'),
        ],
    ],

    'secrets' => [
        'length' => env('CLIENT_SECRET_LENGHT', 32),
        'prefix' => env('CLIENTS_API_KEY_PREFIX'),
    ],
];
