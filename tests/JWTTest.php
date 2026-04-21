<?php


declare( strict_types = 1 );


use JDWX\ACME\JWT;
use PHPUnit\Framework\TestCase;


class JWTTest extends TestCase {


    public function testSignAndVerify() : void {
        $jwk = JWT::createKey();
        $rData = [ 'foo' => 'bar' ];
        $stNonce = '12345';
        $stToken = JWT::sign( $jwk, 'https://example.com/', $stNonce, $rData );
        self::assertTrue( JWT::isConsistent( $stToken ) );
    }


}
