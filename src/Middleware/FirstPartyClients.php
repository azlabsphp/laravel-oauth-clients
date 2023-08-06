<?php

namespace Drewlabs\Laravel\Oauth\Clients\Middleware;

use Closure;
use Drewlabs\Oauth\Clients\Contracts\CredentialsIdentityValidator;
use Drewlabs\Oauth\Clients\Exceptions\AuthorizationException;
use InvalidArgumentException;

final class FirstPartyClients
{
    use InteractsWithRequest;

    /**
     * @var CredentialsIdentityValidator
     */
    private $validator;
    /**
     * @var CredentialsPipelineFactory
     */
    private $factory;

    /**
     * Create middleware class instance
     * 
     * @param CredentialsIdentityValidator $validator 
     * @param CredentialsPipelineFactory $factory 
     */
    public function __construct(CredentialsIdentityValidator $validator, CredentialsPipelineFactory $factory)
    {
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
        $pipeline = $this->factory->create($request);

        // Create credentials using pipeline
        $credentials = call_user_func($pipeline, null);

        // throw an exception if the credentials is not found
        if (null === $credentials) {
            throw new AuthorizationException('authorization headers and cookies not found', 401);
        }

        // Validate throws an exception which might stop request execution flow
        try {
            $client = $this->validator->validate($credentials, [], $this->getRequestIp($request));

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
