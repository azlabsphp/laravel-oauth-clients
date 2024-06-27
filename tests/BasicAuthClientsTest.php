<?php

use Drewlabs\Laravel\Oauth\Clients\Contracts\ClientsRepository;
use Drewlabs\Laravel\Oauth\Clients\Middleware\BasicAuthClients;
use Drewlabs\Laravel\Oauth\Clients\Middleware\CredentialClientsProvider;
use Drewlabs\Laravel\Oauth\Clients\ServerRequest;
use Drewlabs\Laravel\Oauth\Clients\Tests\Stubs\HeadersBag;
use Drewlabs\Laravel\Oauth\Clients\Tests\Stubs\Callback;
use Drewlabs\Laravel\Oauth\Clients\Tests\Stubs\Request;
use Drewlabs\Oauth\Clients\BasicAuthorizationCredentialsFactory;
use Drewlabs\Oauth\Clients\Contracts\SecretClientInterface;
use Drewlabs\Oauth\Clients\Contracts\Validatable;
use Drewlabs\Oauth\Clients\Exceptions\AuthorizationException;
use Drewlabs\Oauth\Clients\VerifyPlainTextSecretEngine;
use PHPUnit\Framework\InvalidArgumentException;
use PHPUnit\Framework\MockObject\Exception;
use PHPUnit\Event\NoPreviousThrowableException;
use PHPUnit\Framework\TestCase;
use PHPUnit\Framework\MockObject\MockObject;

class BasicAuthClientsTest extends TestCase
{

    /**
     * @return BasicAuthClients 
     * @throws InvalidArgumentException 
     * @throws Exception 
     * @throws NoPreviousThrowableException 
     */
    private function createBasicAuthMiddleware($repository = null, $secretVerifier = null)
    {
        $serverRequest = new ServerRequest;
        $clientsProvider = new CredentialClientsProvider(
            new BasicAuthorizationCredentialsFactory($serverRequest),
            new VerifyPlainTextSecretEngine,
            $repository ?? $this->createMock(ClientsRepository::class),
        );
        return new BasicAuthClients($serverRequest, $clientsProvider);
    }

    public function test_basic_auth_clients_throws_authorization_exception_case_request_does_not_have_basic_auth_header()
    {
        // Initialize
        $middleware = $this->createBasicAuthMiddleware();


        $this->expectException(AuthorizationException::class);
        $this->expectExceptionMessage('basic auth client not found');

        // Mock request header function
        /**
         * @var HeadersBag&MockObject
         */
        $headers = $this->createMock(HeadersBag::class);

        $headers->expects($this->once())
            ->method('get')
            ->willReturn(null);

        $request = new Request($headers);
        $next = $this->createMock(Callback::class);

        // Act
        $middleware->handle($request, $next);
    }

    public function test_basic_auth_clients_throws_authorization_exception_case_request_has_incorrect_basic_authorization_header()
    {
        $this->expectException(AuthorizationException::class);
        $this->expectExceptionMessage('basic auth client not found');

        // Initialize
        $middleware = $this->createBasicAuthMiddleware();

        // Mock request header function
        /**
         * @var HeadersBag&MockObject
         */
        $headers = $this->createMock(HeadersBag::class);

        // Assert
        $headers->expects($this->once())
            ->method('get')
            ->with('authorization')
            ->willReturn(sprintf('%s', base64_encode('Client:Secret')));

        $request = new Request($headers);
        $next = $this->createMock(Callback::class);

        // Act
        $middleware->handle($request, $next);
    }

    public function test_basic_auth_client_call_next_function_with_request_instance_case_base_64_credentials_is_provided_and_repository_returns_a_client_instance()
    {
        // Initialize
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
            ->willReturn($client);

        $middleware = $this->createBasicAuthMiddleware($repository);

        // Mock request header function
        /**
         * @var HeadersBag&MockObject
         */
        $headers = $this->createMock(HeadersBag::class);
        $request = new Request($headers);
        /** @var Callback&MockObject */
        $next = $this->createMock(Callback::class);

        $headers
            ->method('get')
            ->willReturnCallback(function (string $property, $default = null) {
                switch ($property) {
                    case 'authorization':
                        return sprintf('basic %s', base64_encode('Client:Secret'));
                    default:
                        return $default;
                }
            });

        $next->expects($this->once())
            ->method('__invoke')
            ->willReturn($response = new stdClass);

        // Act
        $result = $middleware->handle($request, $next);

        // Assert
        $this->assertEquals($response, $result);
    }
}
