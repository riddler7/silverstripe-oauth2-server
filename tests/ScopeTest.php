<?php

namespace AdvancedLearning\Oauth2Server\Tests;

use AdvancedLearning\Oauth2Server\Extensions\GroupExtension;
use AdvancedLearning\Oauth2Server\Repositories\ClientRepository;
use AdvancedLearning\Oauth2Server\Repositories\ScopeRepository;
use AdvancedLearning\Oauth2Server\Services\ScopeService;
use SilverStripe\Core\Config\Config;
use SilverStripe\Dev\SapphireTest;
use SilverStripe\Security\Group;
use SilverStripe\Security\Member;

class ScopeTest extends SapphireTest
{
    protected static $fixture_file = 'tests/OAuthFixture.yml';

    /**
     * Setup test environment.
     */
    public function setUp()
    {
        // add GroupExtension for scopes
        Config::forClass(Group::class)->merge('extensions', [GroupExtension::class]);

        parent::setUp();
    }

    /**
     * Tests whether scopes work on Members through Groups
     */
    public function testMemberHasScope()
    {
        $service = new ScopeService();
        $member = $this->objFromFixture(Member::class, 'member1');

        $this->assertTrue($service->hasScope('scope1', $member), 'Member should have scope1');
        $this->assertFalse($service->hasScope('scope2', $member), 'Member should not have scope2');
    }

    /**
     * Tests whether scopes on Clients works
     */
    public function testClientHasScope()
    {
        $scopeRepo = new ScopeRepository();
        $scopeList = ['members', 'scope1', 'scope2'];
        $scopes = [];

        foreach ($scopeList as $scope) {
            $scopes[] = $scopeRepo->getScopeEntityByIdentifier($scope);
        }

        $clientEntity = (new ClientRepository())->getClientEntity(
            'Thisisanidentifier',
            'client_credentials',
            'Thisisareallybadsecret'
        );

        $finalizedScopes = $scopeRepo->finalizeScopes(
            $scopes,
            'client_credentials',
            $clientEntity
        );

        $finalScopes = [];
        // convert into array of strings
        foreach ($finalizedScopes as $scope) {
            $finalScopes[] = $scope->getIdentifier();
        }

        $this->assertTrue(in_array('members', $finalScopes), 'Should have members scope');
        $this->assertTrue(in_array('scope1', $finalScopes), 'Should have scope1 scope');
        $this->assertFalse(in_array('scope2', $finalScopes), 'Should not have scope2 scope');
    }
}
