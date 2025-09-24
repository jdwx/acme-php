<?php


declare( strict_types = 1 );


namespace JDWX\ACME\Commands;


use JDWX\ACME\Command;
use JDWX\Args\Arguments;
use JDWX\Json\Json;


class CommandOrder extends Command {


    protected const string COMMAND = 'order';

    protected const string HELP    = 'Get order details for a hostname.';

    protected const string USAGE   = 'order <hostname>';


    protected function run( Arguments $args ) : void {
        $stName = $args->shiftStringEx();
        $args->end();
        $nstURL = $this->cli()->loadOrderURL( $stName );
        if ( ! is_string( $nstURL ) ) {
            $this->error( "Order not found: {$stName}" );
            return;
        }
        $r = $this->client->order( $nstURL );
        echo Json::encodePretty( $r ), "\n";
    }


}
