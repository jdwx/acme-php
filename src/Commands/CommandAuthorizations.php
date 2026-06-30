<?php


declare( strict_types = 1 );


namespace JDWX\ACME\Commands;


use JDWX\ACME\CliArguments;
use JDWX\ACME\Command;
use JDWX\Json\Json;


class CommandAuthorizations extends Command {


    protected const string COMMAND = 'authorizations';

    protected const string HELP    = 'List the authorizations for a hostname.';

    protected const string USAGE   = '<hostname>';


    protected function run( CliArguments $args ) : void {
        $order = $args->shiftOrderEx();
        $stName = $order->nameEx();
        $args->end();
        $rAuths = $this->client->authorizationsByName( $order, $stName );
        foreach ( $rAuths as $rAuth ) {
            echo Json::encodePretty( $rAuth ), "\n";
        }
    }


}
