<?php

namespace AdvancedLearning\Oauth2Server\Models;

use function base64_encode;
use SilverStripe\Forms\FieldList;
use SilverStripe\Forms\GridField\GridField;
use SilverStripe\Forms\GridField\GridFieldConfig_RelationEditor;
use SilverStripe\ORM\DataObject;

/**
 * Stores ClientEntity information.
 *
 * @package AdvancedLearning\Oauth2Server\Models
 *
 * @property string $Grants
 * @property string $Name
 * @property string $Secret
 * @property string $Identifier
 */
class Client extends DataObject
{
    private static $table_name = 'OauthClient';

    /**
     * Whether Clients have scopes. The relation is always created, but if set to false will
     * be hidden from CMS.
     *
     * @var bool
     * @config
     */
    private static $has_scopes = true;

    private static $db = [
        'Name' => 'Varchar(100)',
        'Grants' => 'Varchar(255)',
        'Secret' => 'Varchar(255)',
        'Identifier' => 'Varchar(255)'
    ];

    private static $summary_fields = [
        'Name'
    ];

    private static $many_many = [
        'Scopes' => Scope::class
    ];

    public function updateCMSFields(FieldList $fields)
    {
        if (self::config()->get('has_scopes')) {
            $fields->addFieldToTab('Root.Oauth', GridField::create(
                'Scopes',
                'Scopes',
                $this->owner->Scopes(),
                GridFieldConfig_RelationEditor::create()
            ));
        }
    }

    /**
     * Checks whether this ClientEntity has the given grant type.
     *
     * @param string $grantType The grant type to check.
     *
     * @return boolean
     */
    public function hasGrantType($grantType)
    {
        $grants = explode(',', $this->Grants);

        return !empty($grants) && in_array($grantType, $grants);
    }

    /**
     * On before write. Generate a secret if we don't have one.
     */
    public function onBeforeWrite()
    {
        parent::onBeforeWrite();

        if (empty($this->Secret)) {
            $this->Secret = $this->generateSecret();
        }

        if (empty($this->Identifier)) {
            $this->Identifier = $this->generateSecret();
        }
    }

    /**
     * Generate a random secret.
     *
     * @return string
     */
    protected function generateSecret()
    {
        return base64_encode(random_bytes(32));
    }
}
