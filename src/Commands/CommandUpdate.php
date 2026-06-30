<?php


declare( strict_types = 1 );


namespace JDWX\ACME\Commands;


use JDWX\ACME\Command;
use JDWX\Args\Arguments;
use JDWX\Json\Json;


class CommandUpdate extends Command {


    protected const string COMMAND = 'update';

    protected const string HELP    = 'Update email address on current account.';

    protected const string USAGE   = '<email-address>';


    protected function run( Arguments $args ) : void {
        $stEmail = $args->shiftEmailAddressEx();
        $args->end();
        $x = $this->client->updateAccount( $stEmail );
        echo Json::encodePretty( $x ), "\n";
    }


}
