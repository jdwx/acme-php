<?php


declare( strict_types = 1 );


namespace JDWX\ACME\Commands;


use JDWX\ACME\CliArguments;
use JDWX\ACME\Command;
use JDWX\ACME\Exceptions\InvalidArgumentException;
use JDWX\Strict\OK;


class CommandRevoke extends Command {


    protected const string COMMAND = 'revoke';

    protected const string HELP    = 'Revoke a certificate.';

    protected const string USAGE   = '<certificate-url> <reason> [signing-key-path]';


    protected function run( CliArguments $args ) : void {
        $order = $args->shiftOrderEx();
        $uRevocationCode = $args->shiftRevocationReasonEx();
        $nstSigningKeyPath = $args->shiftExistingFilename();
        if ( 1 === $uRevocationCode && ! is_string( $nstSigningKeyPath ) ) {
            $nstSigningKeyPath = $this->cfgGet( 'certs-dir' )->asString() . '/' . $order->nameEx() . '.key';
            if ( ! file_exists( $nstSigningKeyPath ) ) {
                throw new InvalidArgumentException( 'Signing key is required for compromised key revocation.' );
            }
        }
        $nstSigningKey = is_string( $nstSigningKeyPath ) ? OK::file_get_contents( $nstSigningKeyPath ) : null;
        $args->end();
        $rsp = $this->client->revoke( $order, $uRevocationCode, $nstSigningKey );
        echo $rsp->__toString(), "\n";
    }


}
