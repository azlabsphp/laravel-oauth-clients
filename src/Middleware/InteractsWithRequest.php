<?php

namespace Drewlabs\Laravel\Oauth\Clients\Middleware;

use Drewlabs\Core\Helpers\Arr;

trait InteractsWithRequest
{

    /**
     * Gets cookie value from the user provided name.
     *
     * @param \Illuminate\Http\Request $request
     * @param string $name
     *
     * @return string|array
     */
    public function getRequestCookie($request, string $name = null)
    {
        return \is_string($name) ? $request->cookies->get($name) : $request->cookies->all();
    }

    /**
     * Get the request client IP address.
     * 
     * @param \Illuminate\Http\Request $request 
     * @return mixed 
     */
    public function getRequestIp($request)
    {
        $reqAddr = \is_array($addresses = $request->ips()) ? Arr::first($addresses) : $addresses;
        return empty($reqAddr) ? $this->getHeader($request, 'X-Real-IP') : $reqAddr;
    }

    /**
     * Get header value for request header name
     * 
     * @param \Illuminate\Http\Request $request 
     * @param string $name 
     * @param mixed $default 
     * @return mixed 
     */
    public function getHeader($request, string $name, $default = null)
    {
        return $request->headers->get($name, $default);
    }


    /**
     * Parse token from the authorization header.
     *
     * @param \Illuminate\Http\Request $request
     * @param string                 $header
     * @param string                 $method
     *
     * @return ?string
     */
    private function getAuthorizationHeader($request, $header = 'authorization', $method = 'bearer')
    {
        $header = $this->getHeader($request, $header);
        if (null === $header) {
            return null;
        }
        $header = is_array($header) ? array_pop($header) : $header;
        if (null === $header) {
            return null;
        }
        if (!$this->startsWith(strtolower($header), $method)) {
            return null;
        }

        return trim(str_ireplace($method, '', $header));
    }

    /**
     * checks if `$haystack` string starts with `$needle`.
     *
     * @return bool
     */
    private function startsWith(string $haystack, string $needle)
    {
        if (version_compare(\PHP_VERSION, '8.0.0') >= 0) {
            return str_starts_with($haystack, $needle);
        }

        return ('' === $needle) || (mb_substr($haystack, 0, mb_strlen($needle)) === $needle);
    }
}
