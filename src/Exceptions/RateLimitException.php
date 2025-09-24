<?php


declare( strict_types = 1 );


namespace JDWX\ACME\Exceptions;


use JDWX\Strict\OK;
use Throwable;


class RateLimitException extends RetryableACMEException {


    private readonly ?int $tmRetryAfter;


    public function __construct( string          $stDetail = '', int $code = 0, ?Throwable $previous = null,
                                 int|string|null $ntmRetryAfter = null ) {
        if ( is_string( $ntmRetryAfter ) ) {
            if ( is_numeric( $ntmRetryAfter ) ) {
                $ntmRetryAfter = intval( $ntmRetryAfter );
            } else {
                $ntmRetryAfter = OK::strtotime( $ntmRetryAfter );
            }
        }
        if ( is_int( $ntmRetryAfter ) ) {
            if ( $ntmRetryAfter < 1_000_000_000 ) {
                $ntmRetryAfter += time();
            }
            $this->tmRetryAfter = $ntmRetryAfter;
        } else {
            $this->tmRetryAfter = null;
        }

        parent::__construct( 'rateLimited', $stDetail, $code, $previous );
    }


    public function getRetryAfter() : ?int {
        return $this->tmRetryAfter;
    }


}
