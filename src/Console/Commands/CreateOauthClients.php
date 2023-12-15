<?php

namespace Drewlabs\Laravel\Oauth\Clients\Console\Commands;

use Drewlabs\Contracts\Support\Actions\Exceptions\InvalidActionException;
use Drewlabs\Contracts\Validator\Validator;
use Drewlabs\Core\Helpers\Str;
use Drewlabs\Oauth\Clients\Contracts\ClientsRepository;
use Drewlabs\Oauth\Clients\NewClient;
use Drewlabs\ServerAuthorizedClient\AuthorizedClientsManager;
use Illuminate\Console\Command;
use InvalidArgumentException as GlobalInvalidArgumentException;
use Symfony\Component\Console\Exception\InvalidArgumentException;
use RuntimeException;
use Symfony\Component\Console\Exception\LogicException;

class CreateOauthClients extends Command
{

    /**
     * @var string
     */
    protected $signature = 'drewlabs:oauth-clients:create '
        . '{name : Name of the client to generate} '
        . '{--id= : Client ID} '
        . '{--secret= : Client Secret} '
        . '{--ips=* : List of Ip Adress to authorize} '
        . '{--app_url= : Client Hostname} '
        . '{--expires_on= : Date Time format of when the Client authorization credentials expires (YYYY-mm-dd H:i:s)} '
        . '{--redirect= : Successful authentication redirect path} '
        . '{--scopes=* : List of scopes that the client id is restrict to} '
        . '{--password : Creates a password authentication client}'
        . '{--personal : Creates a first party authentication client}'
        . '{--provider= : Token Provider Name} ';

    /**
     * 
     * @var string
     */
    protected  $description = 'Command interface for add new authorized client to the list of authorized-clients';


    /**
     * @var ClientsRepository
     */
    private $clientsRepository;

    /**
     * Creates command instances
     * 
     * @param ClientsRepository $clientsRepository 
     * 
     * @throws GlobalInvalidArgumentException 
     * @throws InvalidArgumentException 
     * @throws LogicException 
     */
    public function __construct(ClientsRepository $clientsRepository)
    {
        parent::__construct();
        $this->clientsRepository = $clientsRepository;
    }

    /**
     * Execute command logic
     * 
     * @param AuthorizedClientsManager $manager 
     * @param Validator $validator 
     * @return void 
     * @throws InvalidArgumentException 
     * @throws InvalidActionException 
     * @throws RuntimeException 
     */
    public function handle()
    {
        $ips = $this->option('ips');
        $scopes = $this->option('scopes');
        $id = $this->option('id');
        $newClient = (new NewClient($id, $this->option('personal'), $this->option('password')))
            ->setName($this->argument('name'))
            ->setIpAddresses(empty($ips) ? ['*'] : $ips)
            ->setAppUrl($this->option('app_url'))
            ->setExpiresAt($this->option('expires_on'))
            ->setRevoked(false)
            ->setRedirectUrl($this->option('redirect'))
            ->setProvider($this->option('provider'))
            ->setScopes(empty($scopes) ? [] : $scopes)
            ->setSecret($this->option('secret'));

        $client = null !== $id ? $this->clientsRepository->updateById($id, $newClient) : $this->clientsRepository->create($newClient);

        $this->info('Client successfully created!');
        $this->info(sprintf('Client ID: %s', $client->getKey()));
        $this->info(sprintf('Client Authorized Addresses: %s', Str::join($client->getIpAddressesAttribute(), ', ')));
        $this->info(sprintf('Client Secret: %s', $client->getPlainSecretAttribute()));
        $this->info(sprintf('Client Credential Expiration Date: %s', $client->getExpiresAt()));
    }
}
