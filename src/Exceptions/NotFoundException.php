<?php

namespace AdvancedLearning\Oauth2Server\Exceptions;

use Exception;
use Throwable;

class NotFoundException extends Exception
{
    protected $response;

    /**
     * NotFoundException constructor.
     *
     * @param string         $message  Exception message.
     * @param int            $code     Error code.
     * @param Throwable|null $previous Previous exception.
     */
    public function __construct($message = "", $code = 0, Throwable $previous = null)
    {
        parent::__construct($message, $code, $previous);
    }
}
