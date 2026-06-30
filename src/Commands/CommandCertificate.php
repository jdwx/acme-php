<?php


declare( strict_types = 1 );


namespace JDWX\ACME\Commands;


use JDWX\ACME\Command;
use JDWX\ACME\IOHelper;
use JDWX\Args\Arguments;


class CommandCertificate extends Command {


    protected const string COMMAND = 'certificate';

    protected const string HELP    = 'Fetch a certificate.';

    protected const string USAGE   = 'certificate <hostname>';


    protected function run( Arguments $args ) : void {
        $stName = $args->shiftHostnameEx();
        $args->end();
        $stURL = $this->cli()->loadOrderURLEx( $stName );
        $order = $this->client->order( $stURL );
        if ( ! $order->hasCertificate() ) {
            $this->error( 'Certificate not available.' );
            return;
        }
        $stCertificate = $this->client->certificate( $order );
        $stCertFile = $this->cli()->cfgGet( 'certs-dir' ) . '/' . $stName . '.crt';
        if ( file_exists( $stCertFile ) ) {
            echo "Certificate already exists.\n";
        } else {
            IOHelper::writeFile( $stCertFile, $stCertificate, 0644, true );
            echo "Wrote certificate to {$stCertFile}.\n";
        }
        echo $stCertificate, "\n";
    }


}
