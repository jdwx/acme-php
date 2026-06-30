#!/usr/bin/env php
<?php


declare( strict_types = 1 );


use JDWX\ACME\ACMEv2;
use JDWX\ACME\Arguments;
use JDWX\ACME\Certificate;
use JDWX\ACME\Client;
use JDWX\ACME\Exceptions\AlreadyRevokedException;
use JDWX\App\InteractiveApplication;


require $_composer_autoload_path ?? __DIR__ . '/../vendor/autoload.php';


/**
 * Revoke a certificate using the certificate's own private key (RFC 8555 §7.6).
 *
 * This needs only the certificate and its key, not the ACME account or the
 * issuing order, so it works even after the order URL has been lost. Point it
 * at staging during testing by setting ACME_DIRECTORY_URL.
 */


( new class extends InteractiveApplication {


    protected function main() : int {
        if ( $this->args()->empty() ) {
            $this->fail(
                    "Revoke a certificate using its own key (RFC 8555 §7.6).\n"
                    . "Usage: revoke-cert.php <cert-path> <key-path> [reason]\n"
                    . 'Reasons: ' . implode( ', ', array_keys( ACMEv2::REVOCATION_REASONS ) )
            );
        }
        $stCertPem = $this->args()->shiftExistingFileBodyEx( i_nstRequired: 'Certificate path is required.' );
        $stKeyPem = $this->args()->shiftExistingFileBodyEx( i_nstRequired: 'Private key path is required.' );
        $uReason = $this->args()->shiftRevocationReason() ?? 0;
        $stReason = ACMEv2::revocationReasonCodeToString( $uReason );
        $this->args()->end();

        $rCerts = Certificate::parseChain( $stCertPem );
        if ( [] === $rCerts ) {
            $this->fail( 'No certificate found.' );
        }

        $stDirectoryURL = getenv( 'ACME_DIRECTORY_URL' ) ?: ACMEv2::LE_PRODUCTION_URL;
        $acme = new ACMEv2( $stDirectoryURL );

        $client = new Client( null, $acme );

        # Revocation cannot be undone; show what is about to happen first.
        echo "Revoking certificate:\n";
        echo '  subject:   ', Certificate::getCN( $rCerts[ 0 ] ) ?? '(unknown)', "\n";
        echo "  reason:    {$stReason} ({$uReason})\n";
        echo "  directory: {$stDirectoryURL}\n";

        if ( ! $this->askYN( 'Are you sure? ' ) ) {
            $this->fail( 'Revocation aborted.' );
        }

        try {
            $client->revokeCertificate( $stCertPem, $uReason, $stKeyPem );
        } catch ( AlreadyRevokedException ) {
            echo "Certificate is already revoked. Nothing to do.\n";
            return 0;
        } catch ( Throwable $e ) {
            $this->fail( 'Revocation failed: ' . $e->getMessage() );
        }

        echo "Revoked successfully.\n";

        return 0;

    }


    public function args() : Arguments {
        $args = parent::args();
        assert( $args instanceof Arguments );
        return $args;
    }


    private function fail( string $i_stMessage ) : never {
        fwrite( STDERR, $i_stMessage . "\n" );
        exit( 1 );
    }


    /** @noinspection PhpMissingParentCallCommonInspection */
    protected function newArguments( array $i_argv ) : Arguments {
        return new Arguments( $i_argv );
    }


} )();


