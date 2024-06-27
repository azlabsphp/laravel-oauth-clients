<?php

use Drewlabs\Laravel\Oauth\Clients\Contracts\ClientsRepository;
use Drewlabs\Laravel\Oauth\Clients\Middleware\CredentialClientsProvider;
use Drewlabs\Laravel\Oauth\Clients\Middleware\JwtAuthClients;
use Drewlabs\Laravel\Oauth\Clients\ServerRequest;
use Drewlabs\Laravel\Oauth\Clients\Tests\Stubs\HeadersBag;
use Drewlabs\Laravel\Oauth\Clients\Tests\Stubs\Callback;
use Drewlabs\Laravel\Oauth\Clients\Tests\Stubs\Request;
use Drewlabs\Oauth\Clients\Contracts\ClientInterface;
use Drewlabs\Oauth\Clients\Contracts\CredentialsFactoryInterface;
use Drewlabs\Oauth\Clients\Contracts\SecretClientInterface;
use Drewlabs\Oauth\Clients\Contracts\Validatable;
use Drewlabs\Oauth\Clients\CredentialsFactory;
use Drewlabs\Oauth\Clients\Exceptions\AuthorizationException;
use Drewlabs\Oauth\Clients\JwtAuthorizationHeaderCredentialsFactory;
use Drewlabs\Oauth\Clients\JwtCookieCredentialsFactory;
use Drewlabs\Oauth\Clients\JwtTokenCredentials;
use Drewlabs\Oauth\Clients\VerifyPlainTextSecretEngine;
use PHPUnit\Framework\TestCase;
use PHPUnit\Framework\MockObject\MockObject;

class JwtAuthClientsTest extends TestCase
{


    /**
     * @return BasicAuthClients 
     * @throws InvalidArgumentException 
     * @throws Exception 
     * @throws NoPreviousThrowableException 
     */
    private function createjwtClientsMiddleware($repository = null, CredentialsFactoryInterface  $factory = null, ClientInterface $client  = null)
    {

        if (is_null($client)) {
            $client = $this->createMockForIntersectionOfInterfaces([SecretClientInterface::class, Validatable::class]);
            $client->method('getHashedSecret')
                ->willReturn('MyToken');
            $client->method('getKey')
                ->willReturn('MyClientId');

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
            $factory = new CredentialsFactory(
                new JwtAuthorizationHeaderCredentialsFactory(new ServerRequest, 'AppKey'),
                new JwtCookieCredentialsFactory(new ServerRequest, 'AppKey')
            );
        }
        $serverRequest = new ServerRequest;
        $clientsProvider = new CredentialClientsProvider(
            $factory,
            new VerifyPlainTextSecretEngine,
            $repository
        );
        return new JwtAuthClients($serverRequest, $clientsProvider);
    }

    public function test_jwt_auth_clients_throws_authorization_exception_case_request_does_not_have_jwt_auth_header()
    {
        // Initialize
        $middleware = $this->createjwtClientsMiddleware();

        $this->expectException(AuthorizationException::class);
        $this->expectExceptionMessage('authorization key was not found');
        $this->expectExceptionCode(401);

        // Mock request header function
        /**
         * @var HeadersBag&MockObject
         */
        $headers = $this->createMock(HeadersBag::class);
        /** @var HeadersBag&MockObject */
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
        $this->expectExceptionMessage('authorization key was not found');

        // Initialize
        $factory = new CredentialsFactory(
            new JwtAuthorizationHeaderCredentialsFactory(new ServerRequest, 'AppSecret'),
            new JwtCookieCredentialsFactory(new ServerRequest, 'AppSecret')
        );
        $middleware = $this->createjwtClientsMiddleware(null, $factory);

        // Mock request header function
        /**  @var HeadersBag&MockObject */
        $headers = $this->createMock(HeadersBag::class);
        /** @var HeadersBag&MockObjectc*/
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
        $middleware =  $this->createjwtClientsMiddleware();
        $token = (string)((new JwtTokenCredentials('AppKey'))->withPayload('MyClientId', 'MyToken'));
        // Mock request header function
        /** @var HeadersBag&MockObject */
        $headers = $this->createMock(HeadersBag::class);
        /** @var HeadersBag&MockObject */
        $cookies = $this->createMock(HeadersBag::class);

        $request = new Request($headers, $cookies);
        /** @var Callback&MockObject */
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

        $response = new stdClass;
        $next->expects($this->once())
            ->method('__invoke')
            ->willReturn($response);

        // Act
        $result = $middleware->handle($request, $next);

        // Assert
        $this->assertEquals($response, $result);
    }

    public function test_jwt_auth_client_call_next_function_with_request_instance_case_jwt_credentials_is_resolved_from_request_cookies()
    {
        // Initialize
        $middleware =  $this->createjwtClientsMiddleware();
        $token = (string)((new JwtTokenCredentials('AppKey'))->withPayload('MyClientId', 'MyToken'));
        // Mock request header function
        /** @var HeadersBag&MockObject */
        $headers = $this->createMock(HeadersBag::class);
        /** @var HeadersBag&MockObject */
        $cookies = $this->createMock(HeadersBag::class);
        $request = new Request($headers, $cookies);
        /**  @var Callback&MockObject */
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
