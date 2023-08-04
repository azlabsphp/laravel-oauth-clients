<?php

use Drewlabs\Laravel\Oauth\Clients\Middleware\CredentialsPipelineFactory;
use Drewlabs\Laravel\Oauth\Clients\Tests\Stubs\HeadersBag;
use Drewlabs\Laravel\Oauth\Clients\Tests\Stubs\Request;
use Drewlabs\Oauth\Clients\BasicAuthCredentials;
use PHPUnit\Framework\MockObject\MockObject;
use Drewlabs\Oauth\Clients\Contracts\CredentialsIdentityInterface;
use Drewlabs\Oauth\Clients\Credentials;
use Drewlabs\Oauth\Clients\JwtTokenCredentials;
use PHPUnit\Framework\TestCase;

class CredentialsPipelineFactoryTest extends TestCase
{
    public function test_credentials_pipeline_factory_create_return_a_callable_which_if_called_on_request_with_no_jwt_basic_or_custom_headers_returns_a_null_credentials()
    {
        // Initialize
        $factory = new CredentialsPipelineFactory('AppKey');
        /**
         * @var MockObject&HeadersBag
         */
        $headers = $this->createMock(HeadersBag::class);
        $headers
            ->method('get')
            ->willReturnCallback(function (string $property, $default = null) {
                switch ($property) {
                    default:
                        return $default;
                }
            });
        /**
         * @var MockObject&HeadersBag
         */
        $cookies = $this->createMock(HeadersBag::class);
        $cookies
            ->method('get')
            ->willReturnCallback(function (string $property, $default = null) {
                switch ($property) {
                    default:
                        return $default;
                }
            });
        $request = new Request($headers, $cookies);

        // Act
        $callback = $factory->create($request);

        // Assert
        $isCallback = is_callable($callback);
        $this->assertTrue($isCallback);

        // Assert
        $this->assertNull(call_user_func($callback, null));
    }

    public function test_credentials_pipeline_factory_create_return_a_callable_which_if_called_on_request_with_basic_auth_headers_returns_a_basic_credentials_instance()
    {
        // Initialize
        $factory = new CredentialsPipelineFactory('AppKey');
        /**
         * @var MockObject&HeadersBag
         */
        $headers = $this->createMock(HeadersBag::class);
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
        /**
         * @var MockObject&HeadersBag
         */
        $cookies = $this->createMock(HeadersBag::class);
        $cookies
            ->method('get')
            ->willReturnCallback(function (string $property, $default = null) {
                switch ($property) {
                    default:
                        return $default;
                }
            });
        $request = new Request($headers, $cookies);

        // Act
        $callback = $factory->create($request);
        /**
         * @var CredentialsIdentityInterface
         */
        $credentials = call_user_func($callback, null);
        // Assert
        $this->assertInstanceOf(BasicAuthCredentials::class, $credentials);
        $this->assertEquals('Client', $credentials->getId());
        $this->assertEquals('Secret', $credentials->getSecret());
    }

    public function test_credentials_pipeline_factory_create_return_a_callable_which_if_called_on_request_with_a_valid_jwt_auth_headers_returns_a_jwt_auth_credentials_instance()
    {
        // Initialize
        $factory = new CredentialsPipelineFactory('AppKey', 'bearer');
        /**
         * @var MockObject&HeadersBag
         */
        $headers = $this->createMock(HeadersBag::class);
        $headers
            ->method('get')
            ->willReturnCallback(function (string $property, $default = null) {
                $token = (string)((new JwtTokenCredentials('AppKey'))->withPayload('Client', 'Secret'));
                switch ($property) {
                    case 'authorization':
                        return sprintf('bearer %s', $token);
                    default:
                        return $default;
                }
            });
        /**
         * @var MockObject&HeadersBag
         */
        $cookies = $this->createMock(HeadersBag::class);
        $cookies
            ->method('get')
            ->willReturnCallback(function (string $property, $default = null) {
                switch ($property) {
                    default:
                        return $default;
                }
            });
        $request = new Request($headers, $cookies);

        // Act
        $callback = $factory->create($request);
        /**
         * @var CredentialsIdentityInterface
         */
        $credentials = call_user_func($callback, null);
        // Assert
        $this->assertInstanceOf(JwtTokenCredentials::class, $credentials);
        $this->assertEquals('Client', $credentials->getId());
        $this->assertEquals('Secret', $credentials->getSecret());
    }

    public function test_credentials_pipeline_factory_create_return_a_callable_which_if_called_on_request_with_a_valid_jwt_auth_cookie_returns_a_jwt_auth_credentials_instance()
    {
        // Initialize
        $factory = new CredentialsPipelineFactory('AppKey');
        /**
         * @var MockObject&HeadersBag
         */
        $headers = $this->createMock(HeadersBag::class);
        $headers
            ->method('get')
            ->willReturnCallback(function (string $property, $default = null) {
                switch ($property) {
                    default:
                        return $default;
                }
            });
        /**
         * @var MockObject&HeadersBag
         */
        $cookies = $this->createMock(HeadersBag::class);
        $cookies
            ->method('get')
            ->willReturnCallback(function (string $property, $default = null) {
                $token = (string)((new JwtTokenCredentials('AppKey'))->withPayload('Client', 'Secret'));
                switch ($property) {
                    case 'jwt-cookie':
                        return (string)$token;
                    default:
                        return $default;
                }
            });
        $request = new Request($headers, $cookies);

        // Act
        $callback = $factory->create($request);
        /**
         * @var CredentialsIdentityInterface
         */
        $credentials = call_user_func($callback, null);
        // Assert
        $this->assertInstanceOf(JwtTokenCredentials::class, $credentials);
        $this->assertEquals('Client', $credentials->getId());
        $this->assertEquals('Secret', $credentials->getSecret());
    }

    public function test_credentials_pipeline_factory_create_return_a_callable_which_if_called_on_request_with_a_valid_custom_authorization_headers_returns_a_custom_auth_credentials_instance()
    {
        // Initialize
        $factory = new CredentialsPipelineFactory('AppKey', 'bearer');
        /**
         * @var MockObject&HeadersBag
         */
        $headers = $this->createMock(HeadersBag::class);
        $headers
            ->method('get')
            ->willReturnCallback(function (string $property, $default = null) {
                switch ($property) {
                    case 'x-client-id':
                        return 'Client';
                    case 'x-client-secret':
                        return 'Secret';
                    default:
                        return $default;
                }
            });
        /**
         * @var MockObject&HeadersBag
         */
        $cookies = $this->createMock(HeadersBag::class);
        $cookies
            ->method('get')
            ->willReturnCallback(function (string $property, $default = null) {
                switch ($property) {
                    default:
                        return $default;
                }
            });
        $request = new Request($headers, $cookies);

        // Act
        $callback = $factory->create($request);
        /**
         * @var CredentialsIdentityInterface
         */
        $credentials = call_user_func($callback, null);
        // Assert
        $this->assertInstanceOf(Credentials::class, $credentials);
        $this->assertEquals('Client', $credentials->getId());
        $this->assertEquals('Secret', $credentials->getSecret());
    }


    public function test_credentials_pipeline_factory_create_return_a_callable_which_if_called_on_request_with_a_valid_custom_authorization_cookies_returns_a_credentials_instance()
    {
        // Initialize
        $factory = new CredentialsPipelineFactory('AppKey');
        /**
         * @var MockObject&HeadersBag
         */
        $headers = $this->createMock(HeadersBag::class);
        $headers
            ->method('get')
            ->willReturnCallback(function (string $property, $default = null) {
                switch ($property) {
                    default:
                        return $default;
                }
            });
        /**
         * @var MockObject&HeadersBag
         */
        $cookies = $this->createMock(HeadersBag::class);
        $cookies
            ->method('get')
            ->willReturnCallback(function (string $property, $default = null) {
                switch ($property) {
                    case 'clientid':
                        return 'Client';
                    case 'clientsecret':
                        return 'Secret';
                    default:
                        return $default;
                }
            });
        $request = new Request($headers, $cookies);

        // Act
        $callback = $factory->create($request);
        /**
         * @var CredentialsIdentityInterface
         */
        $credentials = call_user_func($callback, null);
        // Assert
        $this->assertInstanceOf(Credentials::class, $credentials);
        $this->assertEquals('Client', $credentials->getId());
        $this->assertEquals('Secret', $credentials->getSecret());
    }
}
