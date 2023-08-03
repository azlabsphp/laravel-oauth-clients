<?php

use Drewlabs\Core\Helpers\Rand;
use Drewlabs\Laravel\Oauth\Clients\Eloquent\ClientsProvider;
use Drewlabs\Laravel\Oauth\Clients\Eloquent\ClientsRepository;
use Drewlabs\Oauth\Clients\Contracts\ClientInterface;
use Drewlabs\Oauth\Clients\Contracts\CredentialsIdentityInterface;
use Drewlabs\Oauth\Clients\Contracts\SecretClientInterface;
use Drewlabs\Oauth\Clients\Contracts\VerifyClientSecretInterface;
use PHPUnit\Framework\TestCase;
use PHPUnit\Framework\MockObject\MockObject;

class ClientsProviderTest extends TestCase
{
    public function test_clients_provider_returns_null_if_repository_return_null()
    {
        // Initialize
        /**
         * @var MockObject&ClientsRepository
         */
        $repository = $this->createMock(ClientsRepository::class);

        $repository
            ->expects($this->once())
            ->method('findById')
            ->willReturn(null);

        /**
         * @var MockObject&VerifyClientSecretInterface
         */
        $verifier = $this->createMock(VerifyClientSecretInterface::class);

        /**
         * @var MockObject&CredentialsIdentityInterface
         */
        $credentials = $this->createMock(CredentialsIdentityInterface::class);
        $credentials->method('getId')
            ->willReturn(strval(time()));
        $credentials->method('getSecret')
            ->willReturn(Rand::key(32));

        // Act
        $provider = new ClientsProvider($repository, $verifier);
        $result = $provider->findByCredentials($credentials);

        // Assert
        $this->assertNull($result);
    }

    public function test_clients_provider_returns_null_if_repository_returns_client_by_verifier_returns_false()
    {
        // Initialize
        $client = $this->createMock(SecretClientInterface::class);
        /**
         * @var MockObject&ClientsRepository
         */
        $repository = $this->createMock(ClientsRepository::class);

        $repository
            ->expects($this->once())
            ->method('findById')
            ->willReturn($client);

        /**
         * @var MockObject&VerifyClientSecretInterface
         */
        $verifier = $this->createMock(VerifyClientSecretInterface::class);
        $verifier
            ->expects($this->once())
            ->method('verify')
            ->willReturn(false);

        /**
         * @var MockObject&CredentialsIdentityInterface
         */
        $credentials = $this->createMock(CredentialsIdentityInterface::class);
        $credentials->method('getId')
            ->willReturn(strval(time()));
        $credentials->method('getSecret')
            ->willReturn(Rand::key(32));

        // Act
        $provider = new ClientsProvider($repository, $verifier);
        $result = $provider->findByCredentials($credentials);

        // Assert
        $this->assertNull($result);
    }

    public function test_clients_provider_returns_client_if_repository_returns_client_and_veifier_returns_true()
    {
        // Initialize
        $client = $this->createMock(SecretClientInterface::class);
        /**
         * @var MockObject&ClientsRepository
         */
        $repository = $this->createMock(ClientsRepository::class);
        $repository
            ->expects($this->once())
            ->method('findById')
            ->willReturn($client);

        /**
         * @var MockObject&VerifyClientSecretInterface
         */
        $verifier = $this->createMock(VerifyClientSecretInterface::class);
        $verifier
            ->expects($this->once())
            ->method('verify')
            ->willReturn(true);

        /**
         * @var MockObject&CredentialsIdentityInterface
         */
        $credentials = $this->createMock(CredentialsIdentityInterface::class);
        $credentials->method('getId')
            ->willReturn(strval(time()));
        $credentials->method('getSecret')
            ->willReturn(Rand::key(32));

        // Act
        $provider = new ClientsProvider($repository, $verifier);
        $result = $provider->findByCredentials($credentials);

        // Assert
        $this->assertInstanceOf(ClientInterface::class, $result);
    }
}
