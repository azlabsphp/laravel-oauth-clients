<?php

use Drewlabs\Core\Helpers\Rand;
use Drewlabs\Core\Helpers\UUID;
use Drewlabs\Laravel\Oauth\Clients\Contracts\AttributesAware;
use Drewlabs\Laravel\Oauth\Clients\Eloquent\ClientsRepository;
use Drewlabs\Laravel\Oauth\Clients\Tests\Stubs\NewClientFactory;
use Drewlabs\Oauth\Clients\Contracts\ClientInterface;
use Drewlabs\Oauth\Clients\Contracts\HashesClientSecret;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Support\Collection;
use PHPUnit\Framework\TestCase;
use PHPUnit\Framework\MockObject\MockObject;

class ClientsRepositoryTest extends TestCase
{

    public function test_client_repository_find_by_user_id_returns_empty_array_if_builder_returns_an_empty_collection()
    {
        //Initialize
        /**
         * @var Builder&MockObject
         */
        $builder  = $this->createMock(Builder::class);

        $builder->expects($this->once())
            ->method('where')
            ->with('user_id', '1')
            ->willReturn($builder);

        $builder->expects($this->once())
            ->method('get')
            ->willReturn(new Collection([]));


        $hashSecret = $this->createMock(HashesClientSecret::class);

        $repository = new ClientsRepository($builder, $hashSecret);

        // Act
        $result = $repository->findByUserId(1);

        // Assert
        $this->assertTrue(empty($result));
    }

    public function test_client_repository_return_an_array_of_client_interface_if_builder_returns_a_non_empty_collection()
    {
        //Initialize
        /**
         * @var Builder&MockObject
         */
        $builder  = $this->createMock(Builder::class);

        /**
         * @var AttributesAware&MockObject
         */
        $attributeAware = $this->createMock(AttributesAware::class);
        $attributeAware->method('getAttribute')
            ->willReturn('Test Client');
        $attributeAware->method('toArray')
            ->willReturn([]);

        $builder->expects($this->once())
            ->method('where')
            ->with('user_id', '1')
            ->willReturn($builder);

        $builder->expects($this->once())
            ->method('get')
            ->willReturn(new Collection([$attributeAware]));


        $hashSecret = $this->createMock(HashesClientSecret::class);

        $repository = new ClientsRepository($builder, $hashSecret);

        // Act
        $result = $repository->findByUserId(1);

        // Assert
        $this->assertFalse(empty($result));
        $this->assertInstanceOf(ClientInterface::class, $result[0]);
    }



    public function test_client_repository_find_by_user_id_returns_null_if_builder_first_return_null()
    {
        //Initialize
        $uuid = UUID::create();
        /**
         * @var Builder&MockObject
         */
        $builder  = $this->createMock(Builder::class);

        $builder->expects($this->once())
            ->method('where')
            ->with('id', $uuid)
            ->willReturn($builder);

        $builder->expects($this->once())
            ->method('first')
            ->willReturn(null);

        $hashSecret = $this->createMock(HashesClientSecret::class);

        $repository = new ClientsRepository($builder, $hashSecret);

        // Act
        $result = $repository->findById($uuid);

        // Assert
        $this->assertNull($result);
    }

    public function test_client_repository_return_a_client_interface_if_builder_first_returns_an_attribute_aware_instance()
    {
        //Initialize
        $uuid = UUID::create();
        /**
         * @var Builder&MockObject
         */
        $builder  = $this->createMock(Builder::class);

        /**
         * @var AttributesAware&MockObject
         */
        $attributeAware = $this->createMock(AttributesAware::class);
        $attributeAware->method('getAttribute')
            ->willReturn('Test Client');
        $attributeAware->method('toArray')
            ->willReturn([]);

        $builder->expects($this->once())
            ->method('where')
            ->with('id', $uuid)
            ->willReturn($builder);

        $builder->expects($this->once())
            ->method('first')
            ->willReturn($attributeAware);


        $hashSecret = $this->createMock(HashesClientSecret::class);

        $repository = new ClientsRepository($builder, $hashSecret);

        // Act
        $result = $repository->findById($uuid);

        // Assert
        $this->assertInstanceOf(ClientInterface::class, $result);
    }

    public function test_client_repository_create_call_builder_create_method_and_return_client_with_secret_key_if_none_is_provided()
    {
        //Initialize
        /**
         * @var AttributesAware&MockObject
         */
        $attributeAware = $this->createMock(AttributesAware::class);
        $plainText = Rand::key(16);
        $id = UUID::ordered();

        /** @var HashesClientSecret&MockObject*/
        $hashSecret = $this->createMock(HashesClientSecret::class);

        $hashSecret->expects($this->once())
            ->method('hashSecret')
            ->willReturn($hashedKey = Rand::key(16));

        /** @var Builder&MockObject */
        $builder  = $this->createMock(Builder::class);

        $builder->expects($this->once())
            ->method('create')
            ->with([
                'id' => $id,
                'name' => 'Test Client',
                'user_id' => null,
                'ip_addresses' => '*' ,
                'secret' => $hashedKey,
                'redirect' => null,
                'provider' => 'local',
                'client_url' => null,
                'expires_on' => null,
                'personal_access_client' => false,
                'password_client' => false,
                'scopes' => [],
                'revoked' => false,
                'api_key' => $plainText
            ])
            ->willReturn($attributeAware);

        $repository = new ClientsRepository($builder, $hashSecret, function () use ($plainText) {
            return $plainText;
        });

        // Act
        $result = $repository->create((new NewClientFactory)->create($id, 'Test Client', null, false, false));

        // Assert
        $this->assertInstanceOf(ClientInterface::class, $result);
        $this->assertEquals($plainText, $result->getPlainTextSecret());
    }

    public function test_client_repository_create_call_builder_create_method_and_return_client_interface_instance()
    {
        //Initialize
        $plainSecret = Rand::key(16);
        /**
         * @var AttributesAware&MockObject
         */
        $attributeAware = $this->createMock(AttributesAware::class);

        /**
         * @var Builder&MockObject
         */
        $builder  = $this->createMock(Builder::class);

        $builder->expects($this->once())
            ->method('create')
            ->willReturn($attributeAware);
        /**
         * @var HashesClientSecret&MockObject
         */
        $hashSecret = $this->createMock(HashesClientSecret::class);

        $hashSecret->expects($this->once())
            ->method('hashSecret')
            ->willReturn(Rand::key(16));

        $repository = new ClientsRepository($builder, $hashSecret, function () use ($plainSecret) {
            return $plainSecret;
        });

        // Act
        $result = $repository->create((new NewClientFactory)->create(null, 'Test Client', null, false, false));

        // Assert
        $this->assertEquals($plainSecret, $result->getPlainSecretAttribute());
    }

    public function test_clients_repository_update_by_id_call_hasher_hash_secret_if_a_secret_key_is_provided()
    {
        //Initialize
        $plainSecret = Rand::key(16);
        $hashedSecret = Rand::key(16);
        $uuid = UUID::create();
        /**
         * @var AttributesAware&MockObject
         */
        $attributeAware = $this->createMock(AttributesAware::class);

        /**
         * @var Builder&MockObject
         */
        $builder  = $this->createMock(Builder::class);

        // Assert
        $builder->expects($this->once())
            ->method('update')
            ->with([
                'secret' => $hashedSecret,
                'name' => 'Test Client',
                'revoked' => false,
                'ip_addresses' => '*',
                'scopes' => [],
                'api_key' => $plainSecret
            ])
            ->willReturn($attributeAware);

        // Assert
        $builder->expects($this->exactly(2))
            ->method('where')
            ->with('id', $uuid)
            ->willReturn($builder);

        /**
         * @var HashesClientSecret&MockObject
         */
        $hashSecret = $this->createMock(HashesClientSecret::class);

        $hashSecret->expects($this->once())
            ->method('hashSecret')
            ->with($plainSecret)
            ->willReturn($hashedSecret);

        $repository = new ClientsRepository($builder, $hashSecret);

        // Act
        $repository->updateById($uuid, (new NewClientFactory)->create(null, 'Test Client', $plainSecret));
    }

    public function test_clients_repository_update_by_id_does_not_call_hasher_hash_secret_if_no_secret_key_is_provided()
    {

        //Initialize
        $hashedSecret = Rand::key(16);
        $uuid = UUID::create();
        /**
         * @var AttributesAware&MockObject
         */
        $attributeAware = $this->createMock(AttributesAware::class);

        /**
         * @var Builder&MockObject
         */
        $builder  = $this->createMock(Builder::class);

        // Assert
        $builder->expects($this->once())
            ->method('update')
            ->with(['name' => 'Test Client', 'revoked' => false, 'ip_addresses' => '*', 'scopes' => []])
            ->willReturn($attributeAware);

        // Assert
        $builder->expects($this->exactly(2))
            ->method('where')
            ->with('id', $uuid)
            ->willReturn($builder);

        /**
         * @var HashesClientSecret&MockObject
         */
        $hashSecret = $this->createMock(HashesClientSecret::class);

        $hashSecret->expects($this->never())
            ->method('hashSecret')
            ->willReturn($hashedSecret);

        $repository = new ClientsRepository($builder, $hashSecret);

        // Act
        $repository->updateById($uuid, (new NewClientFactory)->create(null, 'Test Client'));
    }

    public function test_clients_repository_update_by_id_call_builder_where_and_first_methods()
    {

        //Initialize
        $uuid = UUID::create();
        /**
         * @var AttributesAware&MockObject
         */
        $attributeAware = $this->createMock(AttributesAware::class);

        /**
         * @var Builder&MockObject
         */
        $builder  = $this->createMock(Builder::class);

        $builder
            ->method('update')
            ->with(['name' => 'Test Client', 'revoked' => false, 'ip_addresses' => '*', 'scopes' => []]);

        $builder
            ->method('where')
            ->with('id', $uuid)
            ->willReturn($builder);

        // Assert
        $builder
            ->expects($this->once())
            ->method('first')
            ->willReturn($attributeAware);

        /**
         * @var HashesClientSecret&MockObject
         */
        $hashSecret = $this->createMock(HashesClientSecret::class);

        $repository = new ClientsRepository($builder, $hashSecret);

        // Act
        $repository->updateById($uuid, (new NewClientFactory)->create(null, 'Test Client'));
    }

    public function test_clients_repository_update_by_id_return_a_client_interface_instance_if_builder_where_query_return_a_value()
    {

        //Initialize
        $uuid = UUID::create();
        /**
         * @var AttributesAware&MockObject
         */
        $attributeAware = $this->createMock(AttributesAware::class);

        /**
         * @var Builder&MockObject
         */
        $builder  = $this->createMock(Builder::class);

        $builder
            ->method('update')
            ->with(['name' => 'Test Client', 'revoked' => false, 'ip_addresses' => '*', 'scopes' => []]);

        $builder
            ->method('where')
            ->with('id', $uuid)
            ->willReturn($builder);

        // Assert
        $builder
            ->method('first')
            ->willReturn($attributeAware);

        /**
         * @var HashesClientSecret&MockObject
         */
        $hashSecret = $this->createMock(HashesClientSecret::class);

        $repository = new ClientsRepository($builder, $hashSecret);

        // Act
        $result = $repository->updateById($uuid, (new NewClientFactory)->create(null, 'Test Client'));

        // Assert
        $this->assertInstanceOf(ClientInterface::class, $result);
    }

    public function test_clients_repository_delete_by_id_call_builder_where_and_delete_methods_once()
    {

        //Initialize
        $uuid = UUID::create();

        /**
         * @var Builder&MockObject
         */
        $builder  = $this->createMock(Builder::class);

        // Assert
        $builder
            ->expects($this->once())
            ->method('delete')
            ->with()
            ->willReturn(1);

        // Assert
        $builder
            ->expects($this->once())
            ->method('where')
            ->with('id', $uuid)
            ->willReturn($builder);

        /**
         * @var HashesClientSecret&MockObject
         */
        $hashSecret = $this->createMock(HashesClientSecret::class);
        $repository = new ClientsRepository($builder, $hashSecret);

        // Act
        $result = $repository->deleteById($uuid);

        // Assert 
        $this->assertEquals(1, $result);
    }
}
