<?php


declare( strict_types = 1 );


namespace JDWX\ACME\Commands;


use JDWX\ACME\Certificate;
use JDWX\ACME\Command;
use JDWX\ACME\Exceptions\RuntimeException;
use JDWX\ACME\IOHelper;
use JDWX\Args\Arguments;
use JDWX\Json\Json;
use Jose\Component\KeyManagement\JWKFactory;


class CommandRollover extends Command {


    protected const string COMMAND = 'rollover';

    protected const string HELP    = 'Roll over the account key to a freshly generated key (RFC 8555 §7.3.5).';

    protected const string USAGE   = '';


    protected function run( Arguments $args ) : void {
        $args->end();

        $stKeyPath = $this->cfgGet( 'private-key-path' )->asString();
        $stNewPath = $stKeyPath . '.new';
        $stBackupPath = $stKeyPath . '.bak';

        # Generate the new key and stage it on disk before contacting the
        # server. If the rollover succeeds but a later step fails, the new key
        # is still safely persisted and the account remains recoverable.
        $newKey = Certificate::makeKeyEC();
        Certificate::writeKeyPrivate( $stNewPath, $newKey, true );
        $jwkNew = JWKFactory::createFromKeyFile( $stNewPath );

        $rAccount = $this->client->keyChange( $jwkNew );

        # The server accepted the new key. Preserve the old key as a backup and
        # promote the staged key into place.
        IOHelper::writeFile( $stBackupPath, IOHelper::readFile( $stKeyPath ), 0600, true );
        if ( ! @rename( $stNewPath, $stKeyPath ) ) {
            throw new RuntimeException(
                "Account key rolled over but failed to install new key from {$stNewPath} to {$stKeyPath}."
            );
        }

        echo "Account key rolled over. Previous key backed up to {$stBackupPath}.\n";
        echo Json::encodePretty( $rAccount ), "\n";
    }


}
