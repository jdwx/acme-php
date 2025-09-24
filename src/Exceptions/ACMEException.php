<?php


declare( strict_types = 1 );


namespace JDWX\ACME\Exceptions;


use Throwable;


class ACMEException extends ServerException {


    public function __construct( private readonly string $stType = '', string $stDetail = '',
                                 int                     $code = 0, ?Throwable $previous = null ) {
        $message = "ACME Error: $stType: $stDetail";
        parent::__construct( $message, $code, $previous );
    }


    public function getType() : string {
        return $this->stType;
    }


}
