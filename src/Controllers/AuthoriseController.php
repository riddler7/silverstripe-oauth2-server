<?php

namespace AdvancedLearning\Oauth2Server\Controllers;

use AdvancedLearning\Oauth2Server\AuthorizationServer\Generator;
use Exception;
use GuzzleHttp\Psr7\Response;
use League\OAuth2\Server\Exception\OAuthServerException;
use Psr\Http\Message\ResponseInterface;
use Robbie\Psr7\HttpRequestAdapter;
use Robbie\Psr7\HttpResponseAdapter;
use SilverStripe\Control\Controller;
use SilverStripe\Control\HTTP;
use SilverStripe\Control\HTTPRequest;
use SilverStripe\Control\HTTPResponse;
use SilverStripe\Core\Config\Config;

class AuthoriseController extends Controller
{
    /**
     * Cors default config
     *
     * @config
     * @var array
     */
    private static $cors = [
        'Enabled' => false, // Off by default
        'Allow-Origin' => [], // List of all allowed origins; Deny by default
        'Allow-Headers' => 'Authorization, Content-Type',
        'Allow-Methods' => 'GET, POST, OPTIONS',
        'Max-Age' => 86400, // 86,400 seconds = 1 day.
        'Allow-Credentials' => ''
    ];

    /**
     * @var Generator
     */
    protected $serverGenerator;

    /**
     * AuthoriseController constructor. If no Authorization Service is passed a default one is created.
     *
     * @param Generator $serverGenerator
     */
    public function __construct(Generator $serverGenerator)
    {
        $this->serverGenerator = $serverGenerator;
        parent::__construct();
    }

    /**
     * Handles authorisation.
     *
     * @return HTTPResponse
     */
    public function index(): HTTPResponse
    {
        if ($this->getRequest()->httpMethod() === 'OPTIONS') {
            return $this->handleOptions($this->getRequest());
        }

        $body = null;
        $contentType = $this->getRequest()->getHeader('Content-Type');

        if (stripos($contentType, 'application/json') !== false) {
            $body = json_decode($this->getRequest()->getBody(), true);
        } else {
            $body = $this->getRequest()->postVars();
        }

        if (empty($body)) {
            return $this->getErrorResponse(
                'No parameters could be found in request body. Did you correctly set the Content-Type header?',
                500
            );
        }

        // request needs parsed body
        $psrRequest = (new HttpRequestAdapter())->toPsr7($this->getRequest())
            ->withParsedBody($body);
        $psrResponse = new Response();

        try {
            $authServer = $this->serverGenerator->getServer();
            return $this->addCorsHeaders($this->getRequest(), (new HttpResponseAdapter())
                ->fromPsr7($authServer->respondToAccessTokenRequest($psrRequest, $psrResponse)));
        } catch (OAuthServerException $e) {
            return $this->addCorsHeaders($this->getRequest(), $this->getErrorResponse(
                $e->getMessage(),
                $e->getErrorType(),
                $e->getHttpStatusCode()
            ));
        } catch (Exception $e) {
            return $this->addCorsHeaders($this->getRequest(), $this->getErrorResponse($e->getMessage()));
        }
    }

    protected function getErrorResponse($message, $errorType = 'server_error', $responseCode = 500)
    {
        $response = (new OAuthServerException($message, 100, $errorType, $responseCode))
            ->generateHttpResponse(new Response());

        return $this->convertResponse($response);
    }

    protected function convertResponse(ResponseInterface $response)
    {
        return (new HttpResponseAdapter())->fromPsr7($response);
    }

    /**
     * Update default to add Allow-Credentials
     *
     * @param HTTPRequest $request
     * @param HTTPResponse $response
     * @return HTTPResponse
     */
    public function addCorsHeaders(HTTPRequest $request, HTTPResponse $response)
    {
        $corsConfig = Config::inst()->get(static::class, 'cors');

        // If CORS is disabled don't add the extra headers. Simply return the response untouched.
        if (empty($corsConfig['Enabled'])) {
            return $response;
        }

        // Calculate origin
        $origin = $this->getRequestOrigin($request);

        // Check if valid
        $allowedOrigins = (array)$corsConfig['Allow-Origin'];
        $originAuthorised = $this->validateOrigin($origin, $allowedOrigins);

        if (!$originAuthorised) {
            return $this->getErrorResponse("Unauthorised origin", 'auth_error', 403);
        }

        $response->addHeader('Access-Control-Allow-Origin', $origin);
        $response->addHeader('Access-Control-Allow-Headers', $corsConfig['Allow-Headers']);
        $response->addHeader('Access-Control-Allow-Methods', $corsConfig['Allow-Methods']);
        $response->addHeader('Access-Control-Max-Age', $corsConfig['Max-Age']);
        $response->addHeader('Access-Control-Allow-Credentials', $corsConfig['Allow-Credentials']);

        return $response;
    }

    /**
     * Get (or infer) value of Origin header
     *
     * @param HTTPRequest $request
     * @return string|null
     */
    protected function getRequestOrigin(HTTPRequest $request)
    {
        // Prefer Origin header
        $origin = $request->getHeader('Origin');
        if ($origin) {
            return $origin;
        }

        // Check referer
        $referer = $request->getHeader('Referer');
        if ($referer) {
            // Extract protocol, hostname, and port
            $refererParts = parse_url($referer);
            if (!$refererParts) {
                return null;
            }
            // Rebuild
            $origin = $refererParts['scheme'] . '://' . $refererParts['host'];
            if (isset($refererParts['port'])) {
                $origin .= ':' . $refererParts['port'];
            }
            return $origin;
        }

        return null;
    }

    /**
     * Validate an origin matches a set of allowed origins
     *
     * @param string $origin Origin string
     * @param array $allowedOrigins List of allowed origins
     * @return bool
     */
    protected function validateOrigin($origin, $allowedOrigins)
    {
        if (empty($allowedOrigins) || empty($origin)) {
            return false;
        }

        foreach ($allowedOrigins as $allowedOrigin) {
            if ($allowedOrigin === '*') {
                return true;
            }
            if (strcasecmp($allowedOrigin, $origin) === 0) {
                return true;
            }
        }

        return false;
    }

    /**
     * Use static for config.
     *
     * @param HTTPRequest $request
     * @return HTTPResponse
     */
    protected function handleOptions(HTTPRequest $request)
    {
        $response = HTTPResponse::create();
        $corsConfig = Config::inst()->get(static::class, 'cors');
        if ($corsConfig['Enabled']) {
            // CORS config is enabled and the request is an OPTIONS pre-flight.
            // Process the CORS config and add appropriate headers.
            $response = $this->addCorsHeaders($request, $response);
        } else {
            // CORS is disabled but we have received an OPTIONS request.  This is not a valid request method in this
            // situation.  Return a 405 Method Not Allowed response.
            $response = $this->getErrorResponse("Method Not Allowed", 'auth_error', 405);
        }

        return $response;
    }
}
