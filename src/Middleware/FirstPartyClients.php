<?php

namespace Drewlabs\Laravel\Oauth\Clients\Middleware;

use Closure;
use Drewlabs\Laravel\Oauth\Clients\ServerRequest;
use Drewlabs\Oauth\Clients\Contracts\CredentialsIdentityValidator;
use Drewlabs\Oauth\Clients\CredentialsPipelineFactory;
use Drewlabs\Oauth\Clients\Exceptions\AuthorizationException;
use InvalidArgumentException;

final class FirstPartyClients
{

    /**
     * @var CredentialsIdentityValidator
     */
    private $validator;
    /**
     * @var CredentialsPipelineFactory
     */
    private $factory;

    /**
     * @var ServerRequest
     */
    private $serverRequest;

    /**
     * Create middleware class instance
     * 
     * @param ServerRequest $serverRequest
     * @param CredentialsIdentityValidator $validator 
     * @param CredentialsPipelineFactory $factory 
     */
    public function __construct(
        ServerRequest $serverRequest,
        CredentialsIdentityValidator $validator,
        CredentialsPipelineFactory $factory
    ) {
        $this->serverRequest = $serverRequest;
        $this->validator = $validator;
        $this->factory = $factory;
    }

    /**
     * Handle an incoming request
     * 
     * @param mixed $request 
     * @param Closure $next 
     * @param mixed $scopes 
     * @return mixed 
     * @throws InvalidArgumentException 
     * @throws AuthorizationException 
     */
    public function handle($request, callable $next)
    {
        // Create credentials using pipeline
        $credentials = $this->factory->create($request);

        // throw an exception if the credentials is not found
        if (null === $credentials) {
            throw new AuthorizationException('authorization headers and cookies not found', 401);
        }

        // Validate throws an exception which might stop request execution flow
        try {
            $client = $this->validator->validate($credentials, [], $this->serverRequest->getRequestIp($request));

            // Case client does not have required privileges throw an authorization exception
            if (!$client->firstParty()) {
                throw new AuthorizationException('Client does not have the required privileges');
            }

            // next request
            return $next($request);
        } catch (\Throwable $e) {
            throw new AuthorizationException($e->getMessage(), 401);
        }
    }
}
