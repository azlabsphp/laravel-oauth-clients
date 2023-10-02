<?php

use Drewlabs\Laravel\Oauth\Clients\Middleware\JwtAuthClients;
use Drewlabs\Laravel\Oauth\Clients\ServerRequest;
use Drewlabs\Laravel\Oauth\Clients\Tests\Stubs\HeadersBag;
use Drewlabs\Laravel\Oauth\Clients\Tests\Stubs\Callback;
use Drewlabs\Laravel\Oauth\Clients\Tests\Stubs\Request;
use Drewlabs\Oauth\Clients\Contracts\CredentialsIdentityValidator;
use Drewlabs\Oauth\Clients\Exceptions\AuthorizationException;
use Drewlabs\Oauth\Clients\JwtAuthorizationHeaderCredentialsFactory;
use Drewlabs\Oauth\Clients\JwtCookieCredentialsFactory;
use Drewlabs\Oauth\Clients\JwtTokenCredentials;
use PHPUnit\Framework\TestCase;
use PHPUnit\Framework\MockObject\MockObject;

class JwtAuthClientsTest extends TestCase
{
    public function test_jwt_auth_clients_throws_authorization_exception_case_request_does_not_have_jwt_auth_header()
    {
        // Initialize
        $clientsValidator = $this->createMock(CredentialsIdentityValidator::class);
        $middleware = new JwtAuthClients(new ServerRequest, $clientsValidator, new JwtAuthorizationHeaderCredentialsFactory(new ServerRequest, 'AppKey'), new JwtCookieCredentialsFactory(new ServerRequest, 'AppKey'));


        $this->expectException(AuthorizationException::class);
        $this->expectExceptionMessage('jwt auth string not found');
        $this->expectExceptionCode(401);

        // Mock request header function
        /**
         * @var HeadersBag&MockObject
         */
        $headers = $this->createMock(HeadersBag::class);
        /**
         * @var HeadersBag&MockObject
         */
        $cookies = $this->createMock(HeadersBag::class);

        $headers->expects($this->once())
            ->method('get')
            ->willReturn(null);

        $request = new Request($headers, $cookies);
        $next = $this->createMock(Callback::class);

        // Act
        $middleware->handle($request, $next);
    }

    public function test_jwt_auth_clients_throws_authorization_exception_case_request_has_incorrect_jwt_authorization_header_value()
    {
        $this->expectException(AuthorizationException::class);
        $this->expectExceptionMessage('jwt auth string not found');

        // Initialize
        $clientsValidator = $this->createMock(CredentialsIdentityValidator::class);
        $middleware = new JwtAuthClients(new ServerRequest, $clientsValidator, new JwtAuthorizationHeaderCredentialsFactory(new ServerRequest, 'AppSecret'), new JwtCookieCredentialsFactory(new ServerRequest, 'AppSecret'));

        // Mock request header function
        /**
         * @var HeadersBag&MockObject
         */
        $headers = $this->createMock(HeadersBag::class);
        /**
         * @var HeadersBag&MockObject
         */
        $cookies = $this->createMock(HeadersBag::class);

        // Assert
        $headers->expects($this->once())
            ->method('get')
            ->with('authorization')
            ->willReturn(sprintf('%s', base64_encode('Client:Secret')));

        $request = new Request($headers, $cookies);
        $next = $this->createMock(Callback::class);

        // Act
        $middleware->handle($request, $next);
    }

    public function test_jwt_auth_client_call_next_function_with_request_instance_case_jwt_credentials_is_resolved_from_request_headers()
    {
        // Initialize
        $clientsValidator = $this->createMock(CredentialsIdentityValidator::class);
        $middleware = new JwtAuthClients(new ServerRequest, $clientsValidator, new JwtAuthorizationHeaderCredentialsFactory(new ServerRequest, 'AppKey'), new JwtCookieCredentialsFactory(new ServerRequest, 'AppKey'));
        $token = (string)((new JwtTokenCredentials('AppKey'))->withPayload('Client', 'Secret'));
        // Mock request header function
        /**
         * @var HeadersBag&MockObject
         */
        $headers = $this->createMock(HeadersBag::class);
        /**
         * @var HeadersBag&MockObject
         */
        $cookies = $this->createMock(HeadersBag::class);
        $request = new Request($headers, $cookies);
        /**
         * @var Callback&MockObject
         */
        $next = $this->createMock(Callback::class);

        $headers
            ->method('get')
            ->willReturnCallback(function (string $property, $default = null) use ($token) {
                switch ($property) {
                    case 'authorization':
                        return sprintf('jwt %s', $token);
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

    public function test_jwt_auth_client_call_next_function_with_request_instance_case_jwt_credentials_is_resolved_from_request_cookies()
    {
        // Initialize
        $clientsValidator = $this->createMock(CredentialsIdentityValidator::class);
        $middleware = new JwtAuthClients(new ServerRequest, $clientsValidator, new JwtAuthorizationHeaderCredentialsFactory(new ServerRequest, 'AppKey'), new JwtCookieCredentialsFactory(new ServerRequest, 'AppKey'));
        $token = (string)((new JwtTokenCredentials('AppKey'))->withPayload('Client', 'Secret'));
        // Mock request header function
        /**
         * @var HeadersBag&MockObject
         */
        $headers = $this->createMock(HeadersBag::class);
        /**
         * @var HeadersBag&MockObject
         */
        $cookies = $this->createMock(HeadersBag::class);
        $request = new Request($headers, $cookies);
        /**
         * @var Callback&MockObject
         */
        $next = $this->createMock(Callback::class);

        $headers
            ->method('get')
            ->willReturn(null);


        $cookies
            ->method('get')
            ->willReturnCallback(function (string $property, $default = null) use ($token) {
                switch ($property) {
                    case 'jwt-cookie':
                        return (string)$token;
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
