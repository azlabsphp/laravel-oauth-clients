<?php

use Drewlabs\Laravel\Oauth\Clients\Contracts\ClientsRepository;
use Drewlabs\Laravel\Oauth\Clients\Middleware\CredentialClientsProvider;
use Drewlabs\Laravel\Oauth\Clients\Middleware\FirstPartyClients;
use Drewlabs\Laravel\Oauth\Clients\Tests\Stubs\Callback;
use Drewlabs\Laravel\Oauth\Clients\Tests\Stubs\HeadersBag;
use Drewlabs\Laravel\Oauth\Clients\Tests\Stubs\Request;
use Drewlabs\Oauth\Clients\Contracts\ClientInterface;
use Drewlabs\Oauth\Clients\Contracts\CredentialsFactoryInterface;
use Drewlabs\Oauth\Clients\Contracts\CredentialsIdentityInterface;
use Drewlabs\Oauth\Clients\Contracts\SecretClientInterface;
use Drewlabs\Oauth\Clients\Contracts\Validatable;
use Drewlabs\Oauth\Clients\CredentialsFactory;
use Drewlabs\Oauth\Clients\Exceptions\AuthorizationException;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use Drewlabs\Oauth\Clients\VerifyPlainTextSecretEngine;

class FirstPartyMiddlewareTest extends TestCase
{


    private function createClientsMiddleware(ClientsRepository $repository = null, CredentialsFactoryInterface $factory = null, ClientInterface $client = null)
    {
        if (is_null($client)) {
            $client = $this->createMockForIntersectionOfInterfaces([SecretClientInterface::class, Validatable::class]);
            $client->method('getHashedSecret')
                ->willReturn('Secret');
            $client->method('getKey')
                ->willReturn('Client');

            $client->method('validate')
                ->willReturn(true);
        }
        if (is_null($repository)) {

            /** @var ClientsRepository&MockObject */
            $repository = $this->createMock(ClientsRepository::class);
            $repository->method('findById')
                ->willReturnCallback(function ($property) use ($client) {
                    if ($property === 'MyClientId') {
                        return $client;
                    }
                    return null;
                });

            $repository->method('findByApiKey')
                ->willReturnCallback(function ($property) use ($client) {
                    if ($property === 'MyToken') {
                        return $client;
                    }
                    return null;
                });
        }
        if (is_null($factory)) {
            $factory = $this->createMock(CredentialsFactoryInterface::class);
            $factory->method('create')
                ->willReturn(null);
        }
        $clientsProvider = new CredentialClientsProvider(
            $factory,
            new VerifyPlainTextSecretEngine,
            $repository,
        );
        return new FirstPartyClients($clientsProvider);
    }

    public function test_first_party_clients_middleware_throws_an_authorization_exception_case_credentials_pipeline_factory_returns_a_pipeline_that_returns_null_as_credentials()
    {
        // Assert
        $this->expectException(AuthorizationException::class);
        $this->expectExceptionMessage('access client not found');
        $this->expectExceptionCode(401);

        // Initialize
        /**
         * @var HeadersBag&MockObject
         */
        $headers = $this->createMock(HeadersBag::class);
        $request = new Request($headers);

        /**
         * @var Callback&MockObject
         */
        $next = $this->createMock(Callback::class);
        $next->method('__invoke')
            ->willReturn(new stdClass);
        $middleware = $this->createClientsMiddleware();

        // Act
        $middleware->handle($request, $next);
    }

    public function test_first_party_clients_middleware_returns_next_function_return_value_if_pipeline_factory_creates_a_pipeline_that_returns_a_credentials_instance_with_firstParty_that_returns_true()
    {
        // Initialize
        /**
         * @var HeadersBag&MockObject
         */
        $headers = $this->createMock(HeadersBag::class);
        $request = new Request($headers);

        $credentials = $this->createMock(CredentialsIdentityInterface::class);
        $credentials->method('getId')
            ->willReturn('MyClientId');
        $credentials->method('getSecret')
            ->willReturn('Secret');

        /** @var CredentialsFactory&MockObject */
        $factory = $this->createMock(CredentialsFactory::class);
        $factory->method('create')
            ->willReturn($credentials);

        /** @var MockObject&ClientInterface */
        $client = $this->createMockForIntersectionOfInterfaces([SecretClientInterface::class, Validatable::class]);
        $client->method('getHashedSecret')
            ->willReturn('Secret');
        $client->method('getKey')
            ->willReturn('Client');

        $client->method('validate')
            ->willReturn(true);

        $client->method('firstParty')
            ->willReturn(true);

        /**
         * @var Callback&MockObject
         */
        $next = $this->createMock(Callback::class);
        $next->expects($this->once())
            ->method('__invoke')
            ->willReturn($result = new stdClass);
        $middleware = $this->createClientsMiddleware(null, $factory, $client);

        // Act
        $response = $middleware->handle($request, $next);

        // Assert
        $this->assertEquals($result, $response);
    }

    public function test_first_party_clients_middleware_throws_an_authorization_expection_if_firstParty_method_of_the_client_returns_by_validator_does_not_return_true()
    {
        // Assert
        $this->expectException(AuthorizationException::class);
        $this->expectExceptionMessage('client does not have the required privileges');
        $this->expectExceptionCode(401);

        // Initialize
        /** @var HeadersBag&MockObject */
        $headers = $this->createMock(HeadersBag::class);
        $request = new Request($headers);
       
        $credentials = $this->createMock(CredentialsIdentityInterface::class);
        $credentials->method('getId')
            ->willReturn('MyClientId');
        $credentials->method('getSecret')
            ->willReturn('Secret');

        /** @var CredentialsFactory&MockObject */
        $factory = $this->createMock(CredentialsFactory::class);
        $factory->method('create')
            ->willReturn($credentials);

        /** @var MockObject&ClientInterface */
        $client = $this->createMockForIntersectionOfInterfaces([SecretClientInterface::class, Validatable::class]);
        $client->method('getHashedSecret')
            ->willReturn('Secret');
        $client->method('getKey')
            ->willReturn('Client');

        $client->method('validate')
            ->willReturn(true);

        $client->method('firstParty')
            ->willReturn(false);
    
        $middleware = $this->createClientsMiddleware(null, $factory, $client);

        // Act
        $middleware->handle($request, $this->createMock(Callback::class));
    }
}
