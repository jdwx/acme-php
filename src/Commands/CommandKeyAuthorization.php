<?php


declare( strict_types = 1 );


namespace JDWX\ACME\Commands;


use JDWX\ACME\Command;
use JDWX\Args\Arguments;


class CommandKeyAuthorization extends Command {


    protected const string COMMAND = 'key authorization';

    protected const string HELP    = 'Get the key authorization for a token.';

    protected const string USAGE   = '<token>';


    protected function run( Arguments $args ) : void {
        $stToken = $args->shiftStringEx();
        $args->end();
        echo 'Key: ', $this->client->keyAuthorization( $stToken ), "\n";
        echo 'Hashed: ', $this->client->keyAuthorizationHashed( $stToken ), "\n";
    }


}
