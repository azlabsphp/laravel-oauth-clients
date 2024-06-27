<?php

declare(strict_types=1);

/*
 * This file is part of the drewlabs namespace.
 *
 * (c) Sidoine Azandrew <azandrewdevelopper@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Drewlabs\Laravel\Oauth\Clients\Contracts;

use Drewlabs\Oauth\Clients\Contracts\ClientInterface;

interface RequestClientsProvider
{
    /**
     * Find the request client instance based on request attributes, header, and inputs.
     *
     * @param mixed $request
     */
    public function getRequestClient($request): ?ClientInterface;
}
