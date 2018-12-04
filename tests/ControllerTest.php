<?php

namespace AdvancedLearning\Oauth2Server\Tests;

use AdvancedLearning\Oauth2Server\Controllers\AuthoriseController;
use SilverStripe\Control\HTTPRequest;
use SilverStripe\Control\HTTPResponse_Exception;
use SilverStripe\Core\Injector\Injector;
use SilverStripe\Dev\SapphireTest;

class ControllerTest extends SapphireTest
{
    /**
     * Test origin with cors disabled. Should return 405 "Method Not Allowed" error response.
     */
    public function testOptionsCorsDisabled()
    {
        $request = new HTTPRequest('OPTIONS', '/oauth2/authorise');
        $request->addHeader('Origin', 'www.test.com');
        $controller = $this->getController();
        $controller->setRequest($request);

        $response = $controller->index();

        // error status code
        $this->assertEquals(405, $response->getStatusCode());

        // json response
        $json = json_decode($response->getBody(), true);
        $this->assertEquals('Method Not Allowed', $json['message']);
        $this->assertEquals('auth_error', $json['error']);
    }

    /**
     * Test invalid origin with. Should return 403 "Unauthorised origin" error response.
     */
    public function testOptionsBadOrigin()
    {
        $request = new HTTPRequest('OPTIONS', '/oauth2/authorise');
        $request->addHeader('Origin', 'www.test.com');
        $controller = $this->getController([], true);
        $controller->setRequest($request);

        $response = $controller->index();

        // error status code
        $this->assertEquals(403, $response->getStatusCode());

        // json response
        $json = json_decode($response->getBody(), true);
        $this->assertEquals('Unauthorised origin', $json['message']);
        $this->assertEquals('auth_error', $json['error']);
    }

    public function testOptions()
    {
        $request = new HTTPRequest('OPTIONS', '/oauth2/authorise');
        $request->addHeader('Origin', 'www.test.com');
        $controller = $this->getController(['www.test.com'], true);
        $controller->setRequest($request);

        $response = $controller->index();
        $headers = $response->getHeaders();

        $this->assertEquals('www.test.com', $headers['access-control-allow-origin']);
        $this->assertEquals('GET, POST, OPTIONS', $headers['access-control-allow-methods']);
        $this->assertEquals('Authorization, Content-Type', $headers['access-control-allow-headers']);
        $this->assertEquals(86400, $headers['access-control-max-age']);
    }

    /**
     * @return AuthoriseController
     */
    public function getController($origins = [], $enabled = false)
    {
        $config = AuthoriseController::config();
        $config->update('cors', [
            'Enabled' => $enabled, // Off by default
            'Allow-Origin' => $origins, // List of all allowed origins; Deny by default
            'Allow-Headers' => 'Authorization, Content-Type',
            'Allow-Methods' => 'GET, POST, OPTIONS',
            'Max-Age' => 86400, // 86,400 seconds = 1 day.
            'Allow-Credentials' => ''
        ]);

        return Injector::inst()->create(AuthoriseController::class);
    }
}
