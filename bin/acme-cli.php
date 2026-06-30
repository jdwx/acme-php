#!/usr/bin/env php
<?php
declare( strict_types = 1 );


use JDWX\ACME\Interpreter;


require $_composer_autoload_path ?? __DIR__ . '/../vendor/autoload.php';


( new Interpreter( $argv ?? [] ) )->run();
