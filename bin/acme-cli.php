#!/usr/bin/env php
<?php


use JDWX\ACME\Interpreter;


require $_composer_autoload_path ?? __DIR__ . '/../vendor/autoload.php';



( new Interpreter( $argv ) )->run();
