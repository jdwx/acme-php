<?php


declare( strict_types = 1 );


namespace JDWX\ACME\Commands;


use JDWX\ACME\Command;
use JDWX\Args\Arguments;


class CommandNewAccount extends Command {


    protected const string COMMAND = 'new account';

    protected const string HELP    = 'Create a new ACME account';

    protected const string USAGE   = 'new account [contact-email]';


    protected function run( Arguments $args ) : void {
        $stContact = $args->shiftEmailAddress();
        if ( ! is_string( $stContact ) ) {
            $stContact = $this->cfgGet( 'contact-email' )->asString();
        }
        $kid = $this->client->newAccount( $stContact );
        echo 'Account URL = ', $kid, "\n";
    }


}
