<?php

namespace Drewlabs\Laravel\Oauth\Clients\Http;

use BadMethodCallException;
use Closure;
use Drewlabs\Laravel\Oauth\Clients\Client;
use Drewlabs\Laravel\Oauth\Clients\Contracts\ClientsRepository as AbstractClientsRepository;
use Drewlabs\Oauth\Clients\Contracts\ClientInterface;
use Drewlabs\Oauth\Clients\Contracts\NewClientInterface;
use Psr\Http\Client\ClientInterface as PsrClientInterface;
use Psr\Http\Message\RequestFactoryInterface;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\StreamFactoryInterface;
use Psr\Http\Client\ClientExceptionInterface;

class ClientsRepository implements AbstractClientsRepository
{
    /** @var PsrClientInterface */
    private $client;

    /** @var string */
    private $url;

    /** @var RequestFactoryInterface */
    private $requestFactory;

    /** @var StreamFactoryInterface */
    private $streamFactory;

    /** @var array */
    private $headers = [];

    /**
     * Creates new class instance
     * 
     * @param PsrClientInterface $client 
     * @param RequestFactoryInterface $requestFactory 
     * @param StreamFactoryInterface $streamFactory 
     */
    public function __construct(
        PsrClientInterface $client,
        RequestFactoryInterface $requestFactory,
        StreamFactoryInterface $streamFactory
    ) {
        $this->client = $client;
        $this->requestFactory = $requestFactory;
        $this->streamFactory = $streamFactory;
    }

    public function findByUserId($identifier): array
    {
        throw new BadMethodCallException('findByUserId is not supported');
    }

    public function findById($id): ?ClientInterface
    {
        try {
            $request = $this->writeRequestBody($this->requestFactory->createRequest('GET', sprintf("%s/%s", $this->url, $id)));
            $response = $this->client->sendRequest($this->setHeaders($request->withAddedHeader('content-type', 'application/json')));
            $code = $response->getStatusCode();
            if ($code >= 200 && $code <= 204) {
                return new Client(new AttributesAware(json_decode($response->getBody()->__toString(), true)));
            }
            return null;
        } catch (ClientExceptionInterface $e) {
            return null;
        }
    }

    public function findByApiKey(string $key): ?ClientInterface
    {
        throw new BadMethodCallException('findByApiKey is not supported');
    }

    public function updateById($id, NewClientInterface $attributes, ?Closure $callback = null)
    {
        throw new BadMethodCallException('updateById is not supported');
    }

    public function create(NewClientInterface $attributes, ?Closure $callback = null)
    {
        throw new BadMethodCallException('create is not supported');
    }

    public function deleteById($id, ?Closure $callback = null)
    {
        throw new BadMethodCallException('create is not supported');
    }

    /**
     * The endpoint from which the client is selected.
     *
     * @return static
     */
    public function setUrl(string $uri)
    {
        $this->url = $uri;

        return $this;
    }

    /**
     * Add header to the query client instance.
     *
     * @param mixed $value
     *
     * @return static
     */
    public function addHeader(string $name, $value)
    {
        $this->headers[$name] = $value;

        return $this;
    }

    /**
     * @throws \InvalidArgumentException
     *
     * @return RequestInterface
     */
    private function writeRequestBody(RequestInterface $request, array $body = [])
    {
        return $request->withBody($this->streamFactory->createStream(@\json_encode($body)));
    }

    /**
     * Set request headers on the request instance.
     *
     * @throws \InvalidArgumentException
     *
     * @return RequestInterface
     */
    private function setHeaders(RequestInterface $request)
    {
        $headers = $this->headers ?? [];

        // for each header, we add the header to the request
        foreach ($headers as $name => $header) {
            $request = $request->withHeader($name, $header);
        }
        return $request;
    }
}
