<?php

namespace AdvancedLearning\Oauth2Server\Services;


use AdvancedLearning\Oauth2Server\Exceptions\AuthenticationException;
use AdvancedLearning\Oauth2Server\Repositories\AccessTokenRepository;
use GuzzleHttp\Psr7\Response;
use League\OAuth2\Server\Exception\OAuthServerException;
use League\OAuth2\Server\ResourceServer;
use Robbie\Psr7\HttpRequestAdapter;
use Robbie\Psr7\HttpResponseAdapter;
use SilverStripe\Control\Director;
use SilverStripe\Control\HTTPRequest;
use SilverStripe\Core\Environment;

class AuthenticationService implements Authenticator
{
    protected $server;

    /**
     * AuthenticationService constructor.
     *
     * @param ResourceServer|null $server Optional resource server.
     */
    public function __construct(ResourceServer $server = null)
    {
        $this->server = $server ?: $this->createServer();
    }

    /**
     * Authenticate the request. Adds oauth fields as headers on the request.
     *
     * @param HTTPRequest $request The SilverStripe request object to be authenticated.
     *
     * @return HTTPRequest
     * @throws AuthenticationException
     */
    public function authenticate(HTTPRequest $request): HTTPRequest
    {
        $requestAdapter = new HttpRequestAdapter();
        $responseAdapter = new HttpResponseAdapter();

        // missing vars (cli)
        $this->addMissingServerVariables($requestAdapter);

        $server = $this->getServer();
        $psrRequest = $requestAdapter->toPsr7($request);
        $psrResponse = new Response();

        try {
            $psrRequest = $server->validateAuthenticatedRequest($psrRequest);
        } catch (OAuthServerException $exception) {
            // convert to authentication exception
            throw new AuthenticationException(
                $exception->getMessage(),
                $exception->getCode(),
                $responseAdapter->fromPsr7($exception->generateHttpResponse($psrResponse))
            );
        } catch (\Exception $exception) {
            // convert to authentication exception
            throw new AuthenticationException(
                $exception->getMessage(),
                $exception->getCode(),
                $responseAdapter->fromPsr7(
                    (new OAuthServerException($exception->getMessage(), 0, 'unknown_error', 500))
                        ->generateHttpResponse($psrResponse)
                )
            );
        }

        // strip any oauth headers to prevent client side injection
        foreach ($request->getHeaders() as $name => $value) {
            if (stripos($name, 'oauth') !== false) {
                $request->removeHeader($name);
            }
        }

        // add the request attributes as custom auth headers
        foreach ($psrRequest->getAttributes() as $attribute => $value) {
            // check for empty array, breaks otherwise
            $request->addHeader($attribute, is_array($value) && !count($value) ? '' : $value);
        }

        return $request;
    }

    /**
     * Override the default ResourceServer.
     *
     * @param ResourceServer $v The new ResourceServer to use.
     *
     * @return $this
     */
    public function setServer(ResourceServer $v): Authenticator
    {
        $this->server = $v;
        return $this;
    }

    /**
     * Get the ResourceServer.
     *
     * @return ResourceServer
     */
    public function getServer(): ResourceServer
    {
        return $this->server;
    }

    /**
     * Create a default ResourceServer. Used if one isn't provided.
     *
     * @return ResourceServer
     */
    protected function createServer(): ResourceServer
    {
        // Init our repositories
        $accessTokenRepository = new AccessTokenRepository(); // instance of AccessTokenRepositoryInterface

        // Path to authorization server's public key
        $publicKeyPath = Environment::getEnv('OAUTH_PUBLIC_KEY_PATH');

        // Relative paths to the web root
        $publicKeyPath = str_replace('{BASE_DIR}', Director::baseFolder(), $publicKeyPath);

        // Setup the authorization server
        return new ResourceServer(
            $accessTokenRepository,
            $publicKeyPath
        );
    }

    /**
     * Cli is missing some $_SERVER variables.
     *
     * @param HttpRequestAdapter $adapter
     */
    protected function addMissingServerVariables(HttpRequestAdapter $adapter)
    {
        $vars = $adapter->getServerVars() ?: [];
        $defaults = [
            'SERVER_PORT' => 80,
            'HTTP_HOST' => Environment::getEnv('SS_BASE_URL')
        ];

        foreach ($defaults as $key => $value) {
            if (empty($vars[$key])) {
                $vars[$key] = $value;
            }
        }

        $adapter->setServerVars($vars);
    }
}
