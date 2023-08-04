<?php

use Drewlabs\Laravel\Oauth\Clients\Middleware\Clients;
use Drewlabs\Laravel\Oauth\Clients\Middleware\CredentialsPipelineFactory;
use Drewlabs\Laravel\Oauth\Clients\Tests\Stubs\Callback;
use Drewlabs\Laravel\Oauth\Clients\Tests\Stubs\HeadersBag;
use Drewlabs\Laravel\Oauth\Clients\Tests\Stubs\Request;
use Drewlabs\Oauth\Clients\Contracts\CredentialsIdentityInterface;
use Drewlabs\Oauth\Clients\Contracts\CredentialsIdentityValidator;
use Drewlabs\Oauth\Clients\Exceptions\AuthorizationException;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;

class ClientsMiddlewareTest extends TestCase
{

    public function test_clients_middleware_throws_an_authorization_exception_case_credentials_pipeline_factory_returns_a_pipeline_that_returns_null_as_credentials()
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
         * @var Callback&MockObject
         */
        $callback = $this->createMock(Callback::class);
        $callback->method('__invoke')
            ->willReturn(null);
        /**
         * @var CredentialsPipelineFactory&MockObject
         */
        $pipelineFactory = $this->createMock(CredentialsPipelineFactory::class);
        $pipelineFactory->method('create')
            ->willReturn($callback);
        /**
         * @var Callback&MockObject
         */
        $next = $this->createMock(Callback::class);
        $next->method('__invoke')
            ->willReturn(new stdClass);
        $middleware = new Clients($clientsValidator, $pipelineFactory);

        // Act
        $middleware->handle($request, $next);
    }

    public function test_clients_middleware_returns_next_function_return_value_if_pipeline_factory_creates_a_pipeline_that_returns_a_credentials_instance()
    {
        // Initialize
        /**
         * @var HeadersBag&MockObject
         */
        $headers = $this->createMock(HeadersBag::class);
        $request = new Request($headers);
        $clientsValidator = $this->createMock(CredentialsIdentityValidator::class);
        $credentials = $this->createMock(CredentialsIdentityInterface::class);
        /**
         * @var Callback&MockObject
         */
        $callback = $this->createMock(Callback::class);
        $callback->method('__invoke')
            ->willReturn($credentials);
        /**
         * @var CredentialsPipelineFactory&MockObject
         */
        $pipelineFactory = $this->createMock(CredentialsPipelineFactory::class);
        $pipelineFactory->method('create')
            ->willReturn($callback);
        /**
         * @var Callback&MockObject
         */
        $next = $this->createMock(Callback::class);
        $next->expects($this->once())
            ->method('__invoke')
            ->willReturn($result = new stdClass);
        $middleware = new Clients($clientsValidator, $pipelineFactory);

        // Act
        $response = $middleware->handle($request, $next);

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
        $clientsValidator = $this->createMock(CredentialsIdentityValidator::class);
        $credentials = $this->createMock(CredentialsIdentityInterface::class);
        /**
         * @var Callback&MockObject
         */
        $callback = $this->createMock(Callback::class);
        $callback->method('__invoke')
            ->willReturn($credentials);
        /**
         * @var CredentialsPipelineFactory&MockObject
         */
        $pipelineFactory = $this->createMock(CredentialsPipelineFactory::class);

        // Assert
        $pipelineFactory->expects($this->once())
            ->method('create')
            ->with($request)
            ->willReturn($callback);
        /**
         * @var Callback&MockObject
         */
        $next = $this->createMock(Callback::class);
        $next->method('__invoke');
        $middleware = new Clients($clientsValidator, $pipelineFactory);


        // Act
        $middleware->handle($request, $next);
    }
}
