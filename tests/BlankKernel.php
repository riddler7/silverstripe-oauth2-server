<?php

namespace AdvancedLearning\Oauth2Server\Tests;

use SilverStripe\Core\CoreKernel;

class BlankKernel extends CoreKernel
{
    public function __construct($basePath)
    {
        // Noop
    }
    public function boot($flush = false)
    {
        // Noop
    }
}
