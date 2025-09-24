<?php


declare( strict_types = 1 );


namespace JDWX\ACME\Commands;


use JDWX\ACME\Arguments;
use JDWX\ACME\Certificate;
use JDWX\ACME\Command;
use JDWX\Json\Json;


class CommandFinalize extends Command {


    protected const string COMMAND = 'finalize';

    protected const string HELP    = 'Finalize an order.';

    protected const string USAGE   = 'finalize <host-name>';


    protected function run( Arguments $args ) : void {
        $order = $args->shiftOrderEx();
        $stName = $order->nameEx();
        $args->end();
        $rNames = $order->getNames();

        $stPrivateKeyFile = $this->cfgGet( 'certs-dir' )->asString() . "/{$stName}.key";
        if ( file_exists( $stPrivateKeyFile ) ) {
            $key = Certificate::readKeyPrivate( $stPrivateKeyFile );
            echo "Loaded key.\n";
        } else {
            $key = Certificate::makeKey();
            Certificate::writeKeyPrivate( $stPrivateKeyFile, $key );
            echo "Created key.\n";
        }

        $stCSRFile = $this->cfgGet( 'certs-dir' )->asString() . "/{$stName}.csr";
        if ( file_exists( $stCSRFile ) ) {
            $csr = Certificate::readCSR( $stCSRFile );
            echo "Loaded CSR.\n";
        } else {
            $csr = Certificate::makeCSR( $key, $rNames );
            Certificate::writeCSR( $stCSRFile, $csr );
            echo "Created CSR.\n";
        }
        $r = $this->client->finalize( $order, $csr );
        echo Json::encodePretty( $r ), "\n";
    }


}
