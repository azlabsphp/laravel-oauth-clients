<?php

use Drewlabs\Laravel\Oauth\Clients\Middleware\FirstPartyClients;
use Drewlabs\Laravel\Oauth\Clients\ServerRequest;
use Drewlabs\Laravel\Oauth\Clients\Tests\Stubs\Callback;
use Drewlabs\Laravel\Oauth\Clients\Tests\Stubs\HeadersBag;
use Drewlabs\Laravel\Oauth\Clients\Tests\Stubs\Request;
use Drewlabs\Oauth\Clients\Contracts\ClientInterface;
use Drewlabs\Oauth\Clients\Contracts\CredentialsIdentityInterface;
use Drewlabs\Oauth\Clients\Contracts\CredentialsIdentityValidator;
use Drewlabs\Oauth\Clients\Exceptions\AuthorizationException;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use Drewlabs\Oauth\Clients\CredentialsPipelineFactory;

class FirstPartyMiddlewareTest extends TestCase
{

    public function test_first_party_clients_middleware_throws_an_authorization_exception_case_credentials_pipeline_factory_returns_a_pipeline_that_returns_null_as_credentials()
    {
        // Assert
        $this->expectException(AuthorizationException::class);
        $this->expectExceptionMessage('authorization headers and cookies not found');
        $this->expectExceptionCode(401);

        // Initialize
        /**
         * @var HeadersBag&MockObject
         */
        $headers = $this->createMock(HeadersBag::class);
        $request = new Request($headers);
        $clientsValidator = $this->createMock(CredentialsIdentityValidator::class);
        /**
         * @var CredentialsPipelineFactory&MockObject
         */
        $pipelineFactory = $this->createMock(CredentialsPipelineFactory::class);
        $pipelineFactory->method('create')
            ->willReturn(null);
        /**
         * @var Callback&MockObject
         */
        $next = $this->createMock(Callback::class);
        $next->method('__invoke')
            ->willReturn(new stdClass);
        $middleware = new FirstPartyClients(new ServerRequest, $clientsValidator, $pipelineFactory);

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
        /**
         * @var MockObject&CredentialsIdentityInterface
         */
        $credentials = $this->createMock(CredentialsIdentityInterface::class);
        /**
         * @var MockObject&ClientInterface
         */
        $client = $this->createMock(ClientInterface::class);
        $client->method('firstParty')
            ->willReturn(true);
        /**
         * @var CredentialsIdentityValidator&MockObject
         */
        $clientsValidator = $this->createMock(CredentialsIdentityValidator::class);
        $clientsValidator->method('validate')
            ->willReturn($client);
        /**
         * @var CredentialsPipelineFactory&MockObject
         */
        $pipelineFactory = $this->createMock(CredentialsPipelineFactory::class);
        $pipelineFactory->method('create')
            ->willReturn($credentials);
        /**
         * @var Callback&MockObject
         */
        $next = $this->createMock(Callback::class);
        $next->expects($this->once())
            ->method('__invoke')
            ->willReturn($result = new stdClass);
        $middleware = new FirstPartyClients(new ServerRequest, $clientsValidator, $pipelineFactory);

        // Act
        $response = $middleware->handle($request, $next);

        // Assert
        $this->assertEquals($result, $response);
    }

    public function test_first_party_clients_middleware_throws_an_authorization_expection_if_firstParty_method_of_the_client_returns_by_validator_does_not_return_true()
    {
        // Assert
        $this->expectException(AuthorizationException::class);
        $this->expectExceptionMessage('Client does not have the required privileges');
        $this->expectExceptionCode(401);
        // Initialize
        /**
         * @var HeadersBag&MockObject
         */
        $headers = $this->createMock(HeadersBag::class);
        $request = new Request($headers);
        /**
         * @var MockObject&CredentialsIdentityInterface
         */
        $credentials = $this->createMock(CredentialsIdentityInterface::class);
        /**
         * @var MockObject&ClientInterface
         */
        $client = $this->createMock(ClientInterface::class);
        $client->method('firstParty')
            ->willReturn(false);
        /**
         * @var CredentialsIdentityValidator&MockObject
         */
        $clientsValidator = $this->createMock(CredentialsIdentityValidator::class);
        $clientsValidator->method('validate')
            ->willReturn($client);
        /**
         * @var CredentialsPipelineFactory&MockObject
         */
        $pipelineFactory = $this->createMock(CredentialsPipelineFactory::class);
        $pipelineFactory->method('create')
            ->willReturn($credentials);
        /**
         * @var Callback&MockObject
         */
        $next = $this->createMock(Callback::class);
        $middleware = new FirstPartyClients(new ServerRequest, $clientsValidator, $pipelineFactory);

        // Act
        $middleware->handle($request, $next);

    }

    public function test_first_party_clients_middleware_calls_credentials_pipeline_create_method_only_once_with_request_object()
    {
        // Initialize
        /**
         * @var HeadersBag&MockObject
         */
        $headers = $this->createMock(HeadersBag::class);
        $request = new Request($headers);
        /**
         * @var MockObject&CredentialsIdentityInterface
         */
        $credentials = $this->createMock(CredentialsIdentityInterface::class);
        /**
         * @var MockObject&ClientInterface
         */
        $client = $this->createMock(ClientInterface::class);
        $client->method('firstParty')
            ->willReturn(true);
        /**
         * @var CredentialsIdentityValidator&MockObject
         */
        $clientsValidator = $this->createMock(CredentialsIdentityValidator::class);
        $clientsValidator->method('validate')
            ->willReturn($client);
        /**
         * @var CredentialsPipelineFactory&MockObject
         */
        $pipelineFactory = $this->createMock(CredentialsPipelineFactory::class);

        // Assert
        $pipelineFactory->expects($this->once())
            ->method('create')
            ->with($request)
            ->willReturn($credentials);
        /**
         * @var Callback&MockObject
         */
        $next = $this->createMock(Callback::class);
        $next->expects($this->once())
            ->method('__invoke');
        $middleware = new FirstPartyClients(new ServerRequest, $clientsValidator, $pipelineFactory);


        // Act
        $middleware->handle($request, $next);
    }
}
