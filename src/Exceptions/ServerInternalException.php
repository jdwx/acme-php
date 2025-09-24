<?php


declare( strict_types = 1 );


namespace JDWX\ACME\Exceptions;


use Throwable;


class ServerInternalException extends RetryableACMEException {


    public function __construct( string $stDetail = '', int $code = 0, ?Throwable $previous = null ) {
        parent::__construct( 'serverInternal', $stDetail, $code, $previous );
    }


}
