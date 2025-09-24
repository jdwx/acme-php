<?php


declare( strict_types = 1 );


namespace JDWX\ACME\Commands;


use JDWX\ACME\Arguments;
use JDWX\ACME\Command;
use JDWX\Json\Json;


class CommandCheckChallenge extends Command {


    protected const string COMMAND = 'check challenge';

    protected const string HELP    = 'Check a challenge.';

    protected const string USAGE   = 'check challenge <hostname> <type>';


    protected function run( Arguments $args ) : void {
        $order = $args->shiftOrderEx();
        $stName = $order->nameEx();
        $stType = $args->shiftChallengeTypeEx();
        $args->end();
        $r = $this->client->checkChallenge( $order, $stName, $stType );
        echo Json::encodePretty( $r ), "\n";
    }


}
