<?php /** @noinspection PhpUnused */


declare( strict_types = 1 );


namespace JDWX\ACME;


use JDWX\Args\Exceptions\MissingArgumentException;


class Arguments extends \JDWX\Args\Arguments {


    /** @param list<string> $rArgs */
    public function __construct( private readonly Interpreter $cli, array $rArgs ) {
        parent::__construct( $rArgs );
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


    public function shiftOrder() : ?Order {
        $nstName = $this->shiftString();
        if ( ! is_string( $nstName ) ) {
            return null;
        }
        return $this->cli->loadOrder( $nstName );
    }


    public function shiftOrderEx() : Order {
        $nOrder = $this->shiftOrder();
        if ( $nOrder instanceof Order ) {
            return $nOrder;
        }
        throw new MissingArgumentException( 'Order is required' );
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
