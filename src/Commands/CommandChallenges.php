<?php


declare( strict_types = 1 );


namespace JDWX\ACME\Commands;


use JDWX\ACME\Arguments;
use JDWX\ACME\Command;
use JDWX\Json\Json;


class CommandChallenges extends Command {


    protected const string COMMAND = 'challenges';

    protected const string HELP    = 'List challenges for an order.';

    protected const string USAGE   = 'challenges <hostname> [type]';


    protected function run( Arguments $args ) : void {
        $order = $args->shiftOrderEx();
        $stName = $order->nameEx();
        $nstType = $args->shiftString();
        $args->end();
        $rAuths = $this->client->authorizationsByName( $order, $stName );
        foreach ( $rAuths as $rAuth ) {
            $rChallenges = $rAuth[ 'challenges' ];
            assert( is_array( $rChallenges ) );
            foreach ( $rChallenges as $rChallenge ) {
                assert( is_array( $rChallenge ) );
                if ( $nstType !== null && $rChallenge[ 'type' ] !== $nstType ) {
                    continue;
                }
                if ( array_key_exists( 'token', $rChallenge ) ) {
                    $rChallenge[ 'auth-key' ] = $this->client->keyAuthorizationHashed( $rChallenge[ 'token' ] );
                }
                echo Json::encodePretty( $rChallenge ), "\n";
            }
        }
    }


}
