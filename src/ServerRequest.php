<?php

namespace Drewlabs\Laravel\Oauth\Clients;

use Drewlabs\Core\Helpers\Arr;
use Drewlabs\Oauth\Clients\Contracts\ServerRequestFacade;

class ServerRequest implements ServerRequestFacade
{
    public function getRequestCookie($request, ?string $name = null)
    {
        return \is_string($name) ? $request->cookies->get($name) : $request->cookies->all();
    }

    public function getRequestIp($request)
    {
        $reqAddr = \is_array($addresses = $request->ips()) ? Arr::first($addresses) : $addresses;
        return empty($reqAddr) ? $this->getRequestHeader($request, 'X-Real-IP') : $reqAddr;
    }

    public function getRequestHeader($request, string $name, $default = null)
    {
        return $request->headers->get($name, $default);
    }

    public function getRequestAttribute($request, string $name)
    {
    }

    public function getAuthorizationHeader($request, ?string $method = null)
    {
        $header = $this->getRequestHeader($request, 'authorization');
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
