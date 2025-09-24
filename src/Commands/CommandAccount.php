<?php


declare( strict_types = 1 );


namespace JDWX\ACME\Commands;


use JDWX\ACME\Command;
use JDWX\Args\Arguments;
use JDWX\Json\Json;


class CommandAccount extends Command {


    protected const string COMMAND = 'account';

    protected const string HELP    = 'Set current account by URL.';

    protected const string USAGE   = 'account <account-url...>';


    protected function run( Arguments $args ) : void {
        $stURL = $args->shiftString();
        if ( ! is_string( $stURL ) ) {
            if ( ! $this->cfgHas( 'account-url' ) ) {
                $this->error( 'Account URL required.' );
                return;
            }
            $stURL = $this->cfgGet( 'account-url' )->asString();
            $this->info( '[Using default account URL from configuration.]' );
        }
        $r = $this->client->account( $stURL );
        echo Json::encodePretty( $r ), "\n";
    }


}
