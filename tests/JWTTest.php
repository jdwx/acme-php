<?php


declare( strict_types = 1 );


namespace JDWX\ACME\Tests;


use JDWX\ACME\JWT;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;


#[CoversClass( JWT::class )]
final class JWTTest extends TestCase {


    public function testSignAndVerify() : void {
        $jwk = JWT::createKey();
        $rData = [ 'foo' => 'bar' ];
        $stNonce = '12345';
        $stToken = JWT::sign( $jwk, 'https://example.com/', $stNonce, $rData );
        self::assertTrue( JWT::isConsistent( $stToken ) );
    }


}
