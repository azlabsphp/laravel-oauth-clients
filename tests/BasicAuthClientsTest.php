<?php

use Drewlabs\Laravel\Oauth\Clients\Middleware\BasicAuthClients;
use Drewlabs\Laravel\Oauth\Clients\Tests\Stubs\HeadersBag;
use Drewlabs\Laravel\Oauth\Clients\Tests\Stubs\Callback;
use Drewlabs\Laravel\Oauth\Clients\Tests\Stubs\Request;
use Drewlabs\Oauth\Clients\Contracts\CredentialsIdentityValidator;
use Drewlabs\Oauth\Clients\Exceptions\AuthorizationException;
use PHPUnit\Framework\TestCase;
use PHPUnit\Framework\MockObject\MockObject;

class BasicAuthClientsTest extends TestCase
{
    public function test_basic_auth_clients_throws_authorization_exception_case_request_does_not_have_basic_auth_header()
    {
        // Initialize
        $clientsValidator = $this->createMock(CredentialsIdentityValidator::class);
        $middleware = new BasicAuthClients($clientsValidator);


        $this->expectException(AuthorizationException::class);
        $this->expectExceptionMessage('basic auth string not found');

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
        $this->expectExceptionMessage('basic auth string not found');

        // Initialize
        $clientsValidator = $this->createMock(CredentialsIdentityValidator::class);
        $middleware = new BasicAuthClients($clientsValidator);

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

    public function test_basic_auth_client_call_next_function_with_request_instance_case_base_64_credentials_is_resolved()
    {
        // Initialize
        $clientsValidator = $this->createMock(CredentialsIdentityValidator::class);
        $middleware = new BasicAuthClients($clientsValidator);
        // Mock request header function
        /**
         * @var HeadersBag&MockObject
         */
        $headers = $this->createMock(HeadersBag::class);
        $request = new Request($headers);
        /**
         * @var Callback&MockObject
         */
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
