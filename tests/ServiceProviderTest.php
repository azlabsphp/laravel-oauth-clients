<?php

use Drewlabs\Laravel\Oauth\Clients\Eloquent\ClientsRepository;
use Drewlabs\Laravel\Oauth\Clients\Middleware\Clients;
use Drewlabs\Laravel\Oauth\Clients\Middleware\CredentialsPipelineFactory;
use Drewlabs\Laravel\Oauth\Clients\Middleware\FirstPartyClients;
use Drewlabs\Laravel\Oauth\Clients\Middleware\JwtAuthClients;
use Drewlabs\Laravel\Oauth\Clients\ServiceProvider;
use Drewlabs\Laravel\Oauth\Clients\Tests\Stubs\Config;
use Drewlabs\Oauth\Clients\Argon2iHashClientSecret;
use Drewlabs\Oauth\Clients\Contracts\ClientsRepository as AbstractClientsRepository;
use Drewlabs\Oauth\Clients\Contracts\CredentialsIdentityValidator;
use Drewlabs\Oauth\Clients\Contracts\HashesClientSecret;
use Drewlabs\Oauth\Clients\Contracts\VerifyClientSecretInterface;
use Drewlabs\Oauth\Clients\CredentialsValidator;
use Drewlabs\Oauth\Clients\PasswordVerifyClientSecretEngine;
use Drewlabs\Oauth\Clients\PlainTextHashClientSecret;
use Drewlabs\Oauth\Clients\VerifyPlainTextSecretEngine;
use Illuminate\Container\Container;
use PHPUnit\Framework\TestCase;
use Illuminate\Database\Capsule\Manager as Capsule;

class ServiceProviderTest extends TestCase
{
    protected function setUp(): void
    {
        // Make eloquent globally availaible
        $capsule = new Capsule;
        $capsule->addConnection([
            "driver" => "sqlite",
            "host" => null,
            "database" => ':memory:',
            "username" => null,
            "password" => null
        ]);
        $capsule->setAsGlobal();
        $capsule->bootEloquent();
    }

    public function test_service_provider_register_add_required_bindings_to_application_container()
    {
        // Initialize
        $serviceProvider = new ServiceProvider(Container::getInstance());
        Container::getInstance()->singleton('config', function () {
            return new Config;
        });

        // Act
        $serviceProvider->register();

        // Assert
        $this->assertInstanceOf(ClientsRepository::class, Container::getInstance()->make(AbstractClientsRepository::class));
        $this->assertInstanceOf(Argon2iHashClientSecret::class, Container::getInstance()->get(HashesClientSecret::class));
        $this->assertInstanceOf(PasswordVerifyClientSecretEngine::class, Container::getInstance()->get(VerifyClientSecretInterface::class));

        // Act
        Container::getInstance()->get('config')->set('clients.clients.hash', false);
        // Assert
        $this->assertInstanceOf(PlainTextHashClientSecret::class, Container::getInstance()->get(HashesClientSecret::class));
        $this->assertInstanceOf(VerifyPlainTextSecretEngine::class, Container::getInstance()->get(VerifyClientSecretInterface::class));
        $this->assertInstanceOf(CredentialsValidator::class, Container::getInstance()->get(CredentialsIdentityValidator::class));

        // Prevent failure with key being null
        // Act
        Container::getInstance()->get('config')->set('clients.credentials.jwt.key', 'AppSecret');

        // Assert
        $this->assertInstanceOf(CredentialsPipelineFactory::class, Container::getInstance()->get(CredentialsPipelineFactory::class));
        $this->assertInstanceOf(JwtAuthClients::class, Container::getInstance()->get(JwtAuthClients::class));
        $this->assertInstanceOf(Clients::class, Container::getInstance()->get(Clients::class));
        $this->assertInstanceOf(FirstPartyClients::class, Container::getInstance()->get(FirstPartyClients::class));
    }
}
