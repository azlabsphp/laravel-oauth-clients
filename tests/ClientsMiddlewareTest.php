<?php

use Drewlabs\Laravel\Oauth\Clients\Contracts\ClientsRepository;
use Drewlabs\Laravel\Oauth\Clients\Middleware\ApiKeyClientsProvider;
use Drewlabs\Laravel\Oauth\Clients\Middleware\Clients;
use Drewlabs\Laravel\Oauth\Clients\Middleware\ClientsProvider;
use Drewlabs\Laravel\Oauth\Clients\Middleware\CredentialClientsProvider;
use Drewlabs\Laravel\Oauth\Clients\ServerRequest;
use Drewlabs\Laravel\Oauth\Clients\Tests\Stubs\Callback;
use Drewlabs\Laravel\Oauth\Clients\Tests\Stubs\HeadersBag;
use Drewlabs\Laravel\Oauth\Clients\Tests\Stubs\Request;
use Drewlabs\Oauth\Clients\Contracts\CredentialsFactoryInterface;
use Drewlabs\Oauth\Clients\Contracts\CredentialsIdentityInterface;
use Drewlabs\Oauth\Clients\Contracts\SecretClientInterface;
use Drewlabs\Oauth\Clients\Contracts\Validatable;
use Drewlabs\Oauth\Clients\CredentialsFactory;
use Drewlabs\Oauth\Clients\Exceptions\AuthorizationException;
use Drewlabs\Oauth\Clients\VerifyPlainTextSecretEngine;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;

class ClientsMiddlewareTest extends TestCase
{

    private function createClientsMiddleware(ClientsRepository $repository = null, CredentialsFactoryInterface $factory = null)
    {
        if (is_null($repository)) {
            $client = $this->createMockForIntersectionOfInterfaces([SecretClientInterface::class, Validatable::class]);
            $client->method('getHashedSecret')
                ->willReturn('Secret');
            $client->method('getKey')
                ->willReturn('Client');

            $client->method('validate')
                ->willReturn(true);

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
        $serverRequest = new ServerRequest;
        $clientsProvider = new ClientsProvider(
            new ApiKeyClientsProvider($serverRequest, $repository),
            new CredentialClientsProvider(
                $factory,
                new VerifyPlainTextSecretEngine,
                $repository,
            )
        );
        return new Clients($serverRequest, $clientsProvider);
    }

    public function test_clients_middleware_throws_an_authorization_exception_case_credentials_pipeline_factory_returns_a_pipeline_that_returns_null_as_credentials()
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

        // Act
        $this->createClientsMiddleware()->handle($request, $next);
    }

    public function test_clients_middleware_returns_next_function_return_value_if_credentials_factory_creates_a_credentials_object_and_repository_return_a_client_object()
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
        /**
         * @var Callback&MockObject
         */
        $next = $this->createMock(Callback::class);
        $next->expects($this->once())
            ->method('__invoke')
            ->willReturn($result = new stdClass);

        // Act
        $response = $this->createClientsMiddleware(null, $factory)->handle($request, $next);

        // Assert
        $this->assertEquals($result, $response);
    }

    public function test_clients_middleware_calls_credentials_pipeline_create_method_only_once_with_request_object()
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
        $factory->expects($this->once())
            ->method('create')
            ->with($request)
            ->willReturn($credentials);
        /**
         * @var Callback&MockObject
         */
        $next = $this->createMock(Callback::class);
        $next->method('__invoke');

        // Act
        $this->createClientsMiddleware(null, $factory)->handle($request, $next);
    }


    public function test_clients_middleware_does_not_throw_if_acess_token_header_is_provided_and_repository_findByApiKey_returns_a_client()
    {
        // Initialize
        /**
         * @var HeadersBag&MockObject
         */
        $headers = $this->createMock(HeadersBag::class);
        $request = new Request($headers);
        $client = $this->createMockForIntersectionOfInterfaces([SecretClientInterface::class, Validatable::class]);
        $client->method('validate')
            ->willReturn(true);

        /** @var ClientsRepository&MockObject */
        $repository = $this->createMock(ClientsRepository::class);
        $repository->method('findByApiKey')
            ->willReturnCallback(function ($property) use ($client) {
                if ($property === 'MyToken') {
                    return $client;
                }
                return null;
            });

        /** @var HeadersBag&MockObject */
        $headers = $this->createMock(HeadersBag::class);
        $headers
            ->method('get')
            ->willReturnCallback(function (string $property, $default = null) {
                switch ($property) {
                    case 'authorization':
                        return sprintf('api_key %s', 'MyToken');
                    default:
                        return $default;
                }
            });

        $response = new \stdClass;
        /** @var Callback&MockObject */
        $next = $this->createMock(Callback::class);
        $next->expects($this->once())
            ->method('__invoke')
            ->willReturn($response);

        // Act
        $myResponse = $this->createClientsMiddleware($repository, null)->handle(new Request($headers), $next);

        // Assert
        $this->assertEquals($response, $myResponse);
    }
}
