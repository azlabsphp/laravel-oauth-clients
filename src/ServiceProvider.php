<?php

namespace Drewlabs\Laravel\Oauth\Clients;

use Drewlabs\Laravel\Oauth\Clients\Console\Commands\CreateOauthClients;
use Drewlabs\Laravel\Oauth\Clients\Eloquent\Client;
use Drewlabs\Laravel\Oauth\Clients\Eloquent\ClientsProvider;
use Drewlabs\Laravel\Oauth\Clients\Eloquent\ClientsRepository as EloquentClientsRepository;
use Drewlabs\Laravel\Oauth\Clients\Middleware\JwtAuthClients;
use Drewlabs\Oauth\Clients\Argon2iHashClientSecret;
use Drewlabs\Oauth\Clients\BasicAuthorizationCredentialsFactory;
use Drewlabs\Oauth\Clients\Contracts\ClientsRepository;
use Drewlabs\Oauth\Clients\Contracts\CredentialsIdentityValidator;
use Drewlabs\Oauth\Clients\Contracts\HashesClientSecret;
use Drewlabs\Oauth\Clients\Contracts\VerifyClientSecretInterface;
use Drewlabs\Oauth\Clients\CredentialsPipelineFactory;
use Drewlabs\Oauth\Clients\CredentialsValidator;
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
     * Boot application services
     * 
     * @return void 
     */
    public function boot()
    {
        $this->publishes([
            __DIR__ . '/database/migrations' => $this->app->basePath('database/migrations'),
        ], 'oauth-clients-migrations');

        // Publish configuration files
        $this->publishes([
            __DIR__ . '/config' => $this->app->basePath('config'),
        ], 'oauth-clients-configs');

        if ($this->app->runningInConsole()) {
            $this->commands([CreateOauthClients::class]);
        }
    }

    /**
     * Register application services
     * 
     * @return void 
     */
    public function register()
    {
        $this->mergeConfigFrom(__DIR__ . '/config/clients.php', 'clients');

        $this->app->bind(ClientsRepository::class, EloquentClientsRepository::class);

        $this->app->bind(HashesClientSecret::class, function ($app) {
            $config = $app['config'];
            // Case we are hashing client secreate, we make use of argon2i hasher, else we use plain text hasher
            return boolval($config->get('clients.clients.hash', false)) ? new Argon2iHashClientSecret() : new PlainTextHashClientSecret;
        });

        $this->app->bind(VerifyClientSecretInterface::class, function ($app) {
            $config = $app['config'];
            // Case we are hashing client secrets we make use of password verifier instance, else we make use of plain text verifier 
            return boolval($config->get('clients.clients.hash', false)) ? new PasswordVerifyClientSecretEngine : new VerifyPlainTextSecretEngine;
        });

        $this->app->bind(EloquentClientsRepository::class, function ($app) {
            $config = $app['config'];
            $model = $config->get('clients.clients.model') ?? Client::class;
            return new EloquentClientsRepository(forward_static_call([$model, 'query']), $app[HashesClientSecret::class], $config->get('clients.secrets.length', 32) ?? 32);
        });

        $this->app->bind(CredentialsIdentityValidator::class, function ($app) {
            return new CredentialsValidator($app[ClientsProvider::class]);
        });

        $this->app->bind(BasicAuthorizationCredentialsFactory::class, function () {
            return new BasicAuthorizationCredentialsFactory(new ServerRequest);
        });

        $this->app->bind(JwtAuthorizationHeaderCredentialsFactory::class, function ($app) {
            $config = $app['config'];
            return new JwtAuthorizationHeaderCredentialsFactory(new ServerRequest, $config->get('clients.credentials.jwt.key'), $config->get('clients.credentials.jwt.header', 'jwt'));
        });

        $this->app->bind(JwtCookieCredentialsFactory::class, function ($app) {
            $config = $app['config'];
            return new JwtCookieCredentialsFactory(new ServerRequest, $config->get('clients.credentials.jwt.key'), $config->get('clients.credentials.jwt.cookie', 'jwt-cookie'));
        });

        $this->app->bind(CustomHeadersCredentialsFactory::class, function () {
            return new CustomHeadersCredentialsFactory(new ServerRequest);
        });

        $this->app->bind(CredentialsPipelineFactory::class, function ($app) {
            $factories = [
                $app[BasicAuthorizationCredentialsFactory::class],
                $app[JwtAuthorizationHeaderCredentialsFactory::class],
                $app[JwtCookieCredentialsFactory::class]
            ];
            return new CredentialsPipelineFactory(...$factories);
        });
    }
}
