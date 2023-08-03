<?php


/*
|--------------------------------------------------------------------------
| Authorized clients config
|--------------------------------------------------------------------------
|
| Defines drewlabs/server-authorized-clients packages configurations
|
*/
return [
    'clients' => [
        'model' => null,
        'hash' => false
    ],

    'credentials' => [
        'jwt' => [
            'cookie' => env('JWT_CREDENTIALS_COOKIE_NAME', 'jwt-cookie'),
            'header' => env('JWT_CREDENTIALS_HEADER_NAME', 'jwt'),
            'key' => env('APP_KEY')
        ]
    ],

    'secrets' => [
        'length' => env('CLIENT_SECRET_LENGHT', 32)
    ],
];
