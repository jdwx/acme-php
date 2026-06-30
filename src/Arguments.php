<?php


declare( strict_types = 1 );


namespace JDWX\ACME;


use JDWX\Args\Exceptions\MissingArgumentException;


class Arguments extends \JDWX\Args\Arguments {


    /** @param iterable<string>|string $i_args */
    public function __construct( iterable|string $i_args ) {
        parent::__construct( $i_args );
    }


    public function shiftChallengeType() : ?string {
        return $this->shiftKeyword( [ 'http-01', 'dns-01', 'tls-alpn-01' ] );
    }


    public function shiftChallengeTypeEx() : string {
        $nstType = $this->shiftChallengeType();
        if ( is_string( $nstType ) ) {
            return $nstType;
        }
        throw new MissingArgumentException( 'Challenge type required.' );
    }


    public function shiftRevocationReason() : ?int {
        $st = $this->shiftString();
        if ( ! is_string( $st ) ) {
            return null;
        }
        return ACMEv2::revocationReasonStringToCode( $st );
    }


    public function shiftRevocationReasonEx() : int {
        $nstReason = $this->shiftRevocationReason();
        if ( is_int( $nstReason ) ) {
            return $nstReason;
        }
        throw new MissingArgumentException(
            'Revocation reason is required: '
            . implode( ', ', array_keys( ACMEv2::REVOCATION_REASONS ) )
        );
    }


}
