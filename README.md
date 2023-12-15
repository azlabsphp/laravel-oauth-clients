# Laravel Oauth Clients

`drewlabs/oauth-clients` laravel framework bindings. The library provide laravel developers with eloquent compatible `oauth` client

## Usage

To use library components in your laravel application, please register library service provider in the list of application
service providers:

```config/app.php
return [

    // ...

    'providers' => [

        // ...
        \Drewlabs\Laravel\Oauth\Clients\ServiceProvider::class
        // ...
    ],
    // ...
];
```

Note: Doing the step above might not be required, because the library uses laravel service auto discovery to register the it service provider automatically. But in case of any issue, make sure the service is properly registered.

### Configuration assets

Library components such as client secret hashing, should be configured for components to work properly. Therefore the library comes with basic configuration file that can be imported into your
application configuration using laravel vendor:publish command:

> php artisan vendor:publish --tag=oauth-clients-configs

### Migrations

For easy integration with laravel eloquent, library provides a model for properly working with auth clients. To publish migration files for the eloquent model:

> php artisan vendor:publish --tag=oauth-clients-migrations

**Note** You can use the `--force` flag if the migration already exists and should be overridden

Then you run:

> php artisan migrate # to apply your migration changes

### Creating clients using cli

After the above steps completed, you can go to your command while being in development environment to generate auth client instance:

To create a password client:
> php artisan drewlabs:oauth-clients:create --password

To create a personnal access client:

> php artisan drewlabs:oauth-clients:create <NAME> --personal

**Note** Please use `php artisan drewlabs:oauth-clients:create --help` for more options


**Note** Documentation is still under development to include future changes. Thanks.
