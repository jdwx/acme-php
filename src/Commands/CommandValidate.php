<?php


declare( strict_types = 1 );


namespace JDWX\ACME\Commands;


use JDWX\ACME\Command;
use JDWX\Args\Arguments;
use JDWX\Json\Json;


class CommandValidate extends Command {


    protected const string COMMAND = 'validate';

    protected const string HELP    = 'Validate a challenge.';

    protected const string USAGE   = 'validate <host-name> <type>';


    protected function run( Arguments $args ) : void {
        $stName = $args->shiftStringEx();
        $stType = $args->shiftStringEx();
        $args->end();
        $stURL = $this->cli()->loadOrderURLEx( $stName );
        $order = $this->client->order( $stURL );
        $r = $this->client->validate( $order, $stName, $stType );
        echo Json::encodePretty( $r ), "\n";
    }


}
