<?php

namespace Drewlabs\Laravel\Oauth\Clients\Contracts;

use Drewlabs\Oauth\Clients\Contracts\ApiKeyClientsRepository;
use Drewlabs\Oauth\Clients\Contracts\ClientsRepository as AbstractClientsRepository;

interface ClientsRepository extends AbstractClientsRepository, ApiKeyClientsRepository
{
}
