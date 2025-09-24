<?php


declare( strict_types = 1 );


namespace JDWX\ACME\Commands;


use JDWX\ACME\Command;
use JDWX\Args\Arguments;
use JDWX\Json\Json;


class CommandDirectory extends Command {


    protected const string COMMAND = 'directory';

    protected const string HELP    = 'Show the ACME directory';


    /** @param mixed[] $i_r */
    private static function show( array $i_r, int $i_uOffset ) : void {
        $stPad = str_repeat( ' ', $i_uOffset );
        foreach ( $i_r as $stKey => $xValue ) {
            if ( $xValue === 'https://community.letsencrypt.org/t/adding-random-entries-to-the-directory/33417' ) {
                continue;
            }
            if ( is_array( $xValue ) ) {
                echo "{$stPad}{$stKey}:\n";
                self::show( $xValue, $i_uOffset + 4 );
                continue;
            }
            $stValue = is_string( $xValue )
                ? $xValue
                : Json::encode( $xValue );
            if ( is_int( $stKey ) ) {
                echo "{$stPad}* {$stValue}\n";
            } else {
                echo "{$stPad}{$stKey}:\n{$stPad}    {$stValue}\n";
            }
        }
    }


    protected function run( Arguments $args ) : void {
        $r = $this->client->directory();
        self::show( $r, 0 );
    }


}
