<?php

namespace AdvancedLearning\Oauth2Server\Entities;

use AdvancedLearning\Oauth2Server\Models\Client;
use League\OAuth2\Server\Entities\ClientEntityInterface;
use League\OAuth2\Server\Entities\Traits\ClientTrait;
use League\OAuth2\Server\Entities\Traits\EntityTrait;

class ClientEntity implements ClientEntityInterface
{
    use ClientTrait, EntityTrait;

    /**
     * Create a new client instance.
     *
     * @param string $identifier  The identifier for the client.
     * @param string $name        The name of the client.
     * @param string $redirectUri Redirect Uri.
     */
    public function __construct(string $identifier, string $name, string $redirectUri)
    {
        $this->setIdentifier($identifier);
        $this->name = $name;
        $this->redirectUri = explode(',', $redirectUri);
    }

    /**
     * Gets the Client Model.
     *
     * @return Client|null
     */
    public function getClient()
    {
        return Client::get()->filter(['Identifier' => $this->getIdentifier()])->first();
    }

    /**
     * Checks whether the client has a scope. Only works if it has been configured.
     *
     * @param string $scope
     * @return bool
     */
    public function hasScope(string $scope): bool
    {
        if (!Client::config()->get('has_scopes')) {
            return false;
        }

        $client = $this->getClient();

        return $client && $client->Scopes()->filter([
                'Name' => $scope
            ])->count() > 0;
    }
}
