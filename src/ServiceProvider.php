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

use Drewlabs\Laravel\Oauth\Clients\Console\Commands\CreateOauthClients;
use Drewlabs\Laravel\Oauth\Clients\Contracts\ClientsRepository as AbstractClientsRepository;
use Drewlabs\Laravel\Oauth\Clients\Eloquent\Client;
use Drewlabs\Laravel\Oauth\Clients\Eloquent\ClientsRepository as EloquentClientsRepository;
use Drewlabs\Laravel\Oauth\Clients\Middleware\ApiKeyClients;
use Drewlabs\Laravel\Oauth\Clients\Middleware\ApiKeyClientsProvider;
use Drewlabs\Laravel\Oauth\Clients\Middleware\BasicAuthClients;
use Drewlabs\Laravel\Oauth\Clients\Middleware\Clients;
use Drewlabs\Laravel\Oauth\Clients\Middleware\ClientsProvider;
use Drewlabs\Laravel\Oauth\Clients\Middleware\CredentialClientsProvider;
use Drewlabs\Laravel\Oauth\Clients\Middleware\FirstPartyClients;
use Drewlabs\Laravel\Oauth\Clients\Middleware\JwtAuthClients;
use Drewlabs\Oauth\Clients\Argon2iHashClientSecret;
use Drewlabs\Oauth\Clients\BasicAuthorizationCredentialsFactory;
use Drewlabs\Oauth\Clients\Contracts\ClientsRepository;
use Drewlabs\Oauth\Clients\Contracts\HashesClientSecret;
use Drewlabs\Oauth\Clients\Contracts\VerifyClientSecretInterface;
use Drewlabs\Oauth\Clients\CredentialsFactory;
use Drewlabs\Oauth\Clients\CustomHeadersCredentialsFactory;
use Drewlabs\Oauth\Clients\JwtAuthorizationHeaderCredentialsFactory;
use Drewlabs\Oauth\Clients\JwtCookieCredentialsFactory;
use Drewlabs\Oauth\Clients\PasswordVerifyClientSecretEngine;
use Drewlabs\Oauth\Clients\PlainTextHashClientSecret;
use Drewlabs\Oauth\Clients\VerifyPlainTextSecretEngine;
use Illuminate\Support\ServiceProvider as SupportServiceProvider;

class ServiceProvider extends SupportServiceProvider
{
    /**
     * Boot application services.
     *
     * @return void
     */
    public function boot()
    {
        $this->publishes([
            __DIR__.'/database/migrations' => $this->app->basePath('database/migrations'),
        ], 'oauth-clients-migrations');

        // Publish configuration files
        $this->publishes([
            __DIR__.'/config' => $this->app->basePath('config'),
        ], 'oauth-clients-configs');

        if ($this->app->runningInConsole()) {
            $this->commands([CreateOauthClients::class]);
        }
    }

    /**
     * Register application services.
     *
     * @return void
     */
    public function register()
    {
        $this->mergeConfigFrom(__DIR__.'/config/clients.php', 'clients');

        $this->app->bind(ClientsRepository::class, EloquentClientsRepository::class);
        $this->app->bind(AbstractClientsRepository::class, EloquentClientsRepository::class);

        $this->app->bind(HashesClientSecret::class, static function ($app) {
            $config = $app['config'];

            // Case we are hashing client secreate, we make use of argon2i hasher, else we use plain text hasher
            return (bool) ($config->get('clients.clients.hash', false)) ? new Argon2iHashClientSecret() : new PlainTextHashClientSecret();
        });

        $this->app->bind(VerifyClientSecretInterface::class, static function ($app) {
            $config = $app['config'];

            // Case we are hashing client secrets we make use of password verifier instance, else we make use of plain text verifier
            return (bool) ($config->get('clients.clients.hash', false)) ? new PasswordVerifyClientSecretEngine() : new VerifyPlainTextSecretEngine();
        });

        $this->app->bind(EloquentClientsRepository::class, static function ($app) {
            $config = $app['config'];
            $model = $config->get('clients.clients.model') ?? Client::class;

            return new EloquentClientsRepository(forward_static_call([$model, 'query']), $app[HashesClientSecret::class], $config->get('clients.secrets.length', 32) ?? 32, $config->get('clients.secrets.prefix'));
        });

        $this->app->bind(BasicAuthorizationCredentialsFactory::class, static function () {
            return new BasicAuthorizationCredentialsFactory(new ServerRequest());
        });

        $this->app->bind(JwtAuthorizationHeaderCredentialsFactory::class, static function ($app) {
            $config = $app['config'];

            return new JwtAuthorizationHeaderCredentialsFactory(new ServerRequest(), $config->get('clients.credentials.jwt.key'), $config->get('clients.credentials.jwt.header', 'jwt'));
        });

        $this->app->bind(JwtCookieCredentialsFactory::class, static function ($app) {
            $config = $app['config'];

            return new JwtCookieCredentialsFactory(new ServerRequest(), $config->get('clients.credentials.jwt.key'), $config->get('clients.credentials.jwt.cookie', 'jwt-cookie'));
        });

        $this->app->bind(CustomHeadersCredentialsFactory::class, static function () {
            return new CustomHeadersCredentialsFactory(new ServerRequest());
        });

        $this->app->bind(ApiKeyClientsProvider::class, static function ($app) {
            return new ApiKeyClientsProvider(new ServerRequest(), $app[AbstractClientsRepository::class]);
        });

        $this->app->bind(BasicAuthClients::class, static function ($app) {
            $clientsProvider = new CredentialClientsProvider(
                $app[BasicAuthorizationCredentialsFactory::class],
                $app[VerifyClientSecretInterface::class],
                $app[AbstractClientsRepository::class]
            );

            return new BasicAuthClients(new ServerRequest(), $clientsProvider);
        });

        $this->app->bind(Clients::class, function ($app) {
            return new Clients(new ServerRequest(), $this->createComposedClientsProvider($app));
        });

        $this->app->bind(FirstPartyClients::class, function ($app) {
            return new FirstPartyClients($this->createComposedClientsProvider($app));
        });

        $this->app->bind(JwtAuthClients::class, static function ($app) {
            return new JwtAuthClients(new ServerRequest(), new CredentialClientsProvider(
                new CredentialsFactory(
                    $app[JwtAuthorizationHeaderCredentialsFactory::class],
                    $app[JwtCookieCredentialsFactory::class],
                ),
                $app[VerifyClientSecretInterface::class],
                $app[AbstractClientsRepository::class]
            ));
        });

        $this->app->bind(ApiKeyClients::class, static function ($app) {
            $requestAdapter = new ServerRequest();

            return new ApiKeyClients($requestAdapter, new ApiKeyClientsProvider($requestAdapter, $app[AbstractClientsRepository::class]));
        });
    }

    /**
     * Creates a credentials factory that combines multiple credential factories.
     *
     * @param mixed $app
     *
     * @return CredentialsFactory
     */
    private function createComposedCredentialsFactory($app)
    {
        return new CredentialsFactory(
            $app[BasicAuthorizationCredentialsFactory::class],
            $app[JwtAuthorizationHeaderCredentialsFactory::class],
            $app[JwtCookieCredentialsFactory::class],
            $app[CustomHeadersCredentialsFactory::class]
        );
    }

    /**
     * Creates a composed clients provider instance.
     *
     * @param mixed $app
     *
     * @return ClientsProvider
     */
    private function createComposedClientsProvider($app)
    {
        return new ClientsProvider(
            $app[ApiKeyClientsProvider::class],
            new CredentialClientsProvider(
                $this->createComposedCredentialsFactory($app),
                $app[VerifyClientSecretInterface::class],
                $app[AbstractClientsRepository::class]
            )
        );
    }
}
