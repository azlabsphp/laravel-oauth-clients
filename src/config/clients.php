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

    'auth' => [
        'basic' => [
            'user' => env('BASIC_AUTH_USER'),
            'password' => env('BASIC_AUTH_PW')
        ]
    ],

    'clients' => [
        'model' => null,
        'hash' => false
    ],

    'secrets' => [
        'length' => env('CLIENT_SECRET_LENGHT', 32)
    ],
    'auth' => [
        'middleware' => 'auth'
    ]
];
