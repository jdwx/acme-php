<?php


declare( strict_types = 1 );


namespace JDWX\ACME\Commands;


use JDWX\ACME\Arguments;
use JDWX\ACME\Command;


class CommandRevoke extends Command {


    protected const string COMMAND = 'revoke';

    protected const string HELP    = 'Revoke a certificate.';

    protected const string USAGE   = '<certificate-url>';


    protected function run( Arguments $args ) : void {
        $order = $args->shiftOrderEx();
        $uRevocationCode = $args->shiftRevocationReason() ?? 0;
        $args->end();
        $rsp = $this->client->revoke( $order, $uRevocationCode );
        echo $rsp->__toString(), "\n";
    }


}
