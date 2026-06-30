<?php /** @noinspection PhpUnused */


declare( strict_types = 1 );


namespace JDWX\ACME;


use JDWX\Args\Exceptions\MissingArgumentException;


class CliArguments extends Arguments {


    /** @param list<string> $rArgs */
    public function __construct( private readonly Interpreter $cli, array $rArgs ) {
        parent::__construct( $rArgs );
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


}
