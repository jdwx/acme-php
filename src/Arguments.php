<?php /** @noinspection PhpUnused */


declare( strict_types = 1 );


namespace JDWX\ACME;


use JDWX\ACME\Exceptions\RuntimeException;


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
        throw new RuntimeException( 'Challenge type required.' );
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
        throw new RuntimeException( 'Order not found' );
    }


    public function shiftRevocationReason() : ?int {
        $st = $this->shiftString();
        if ( ! is_string( $st ) ) {
            return null;
        }
        return ACMEv2::revocationReasonStringToCode( $st );
    }


}
