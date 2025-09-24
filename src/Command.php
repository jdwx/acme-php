<?php


declare( strict_types = 1 );


namespace JDWX\ACME;


use JDWX\CLI\AbstractCommand;
use JDWX\Param\IParameter;


abstract class Command extends AbstractCommand {


    protected Client $client;


    /** @param string ...$args */
    protected function cfgGet( ... $args ) : IParameter {
        return $this->cli()->cfgGet( ... $args );
    }


    /** @param string ...$args */
    protected function cfgHas( ... $args ) : bool {
        return $this->cli()->cfgHas( ... $args );
    }


    protected function cli() : Interpreter {
        $x = parent::cli();
        assert( $x instanceof Interpreter );
        return $x;
    }


    abstract protected function run( Arguments $args ) : void;


    public function runOuter( \JDWX\Args\Arguments $args ) : void {
        $this->client = $this->cli()->client();
        parent::runOuter( $args );
    }


}
