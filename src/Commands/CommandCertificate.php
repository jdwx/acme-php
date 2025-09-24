<?php


declare( strict_types = 1 );


namespace JDWX\ACME\Commands;


use JDWX\ACME\Command;
use JDWX\Args\Arguments;


class CommandCertificate extends Command {


    protected const string COMMAND = 'certificate';

    protected const string HELP    = 'Fetch a certificate.';

    protected const string USAGE   = 'certificate <hostname>';


    protected function run( Arguments $args ) : void {
        $stName = $args->shiftStringEx();
        $args->end();
        $stURL = $this->cli()->loadOrderURLEx( $stName );
        $order = $this->client->order( $stURL );
        if ( ! $order->hasCertificate() ) {
            $this->error( 'Certificate not available.' );
            return;
        }
        $rCert = $this->client->certificate( $order );
        $stCertFile = $this->cli()->cfgGet( 'certs-dir' ) . '/' . $stName . '.crt';
        if ( file_exists( $stCertFile ) ) {
            echo "Certificate already exists.\n";
        } else {
            file_put_contents( $stCertFile, $rCert );
            echo "Wrote certificate to {$stCertFile}.\n";
        }
        echo $rCert, "\n";
    }


}
