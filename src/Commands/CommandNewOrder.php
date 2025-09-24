<?php


declare( strict_types = 1 );


namespace JDWX\ACME\Commands;


use JDWX\ACME\Command;
use JDWX\Args\Arguments;
use JDWX\Json\Json;


class CommandNewOrder extends Command {


    protected const string COMMAND = 'new order';

    protected const string HELP    = 'Create a new order';

    protected const string USAGE   = 'new order <domain-name...>';


    protected function run( Arguments $args ) : void {
        $rNames = $args->endWithArray();
        $r = $this->client->newOrder( $rNames );
        echo Json::encodePretty( $r ), "\n";
        $stLocation = $r[ 'location' ];
        assert( is_string( $stLocation ) );
        $this->cli()->saveOrder( $rNames, $stLocation );
        echo "Order created:\n";
    }


}
