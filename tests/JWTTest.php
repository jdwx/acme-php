<?php


declare( strict_types = 1 );


namespace JDWX\ACME\Tests;


use JDWX\ACME\Base64Url;
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


    public function testSignWithNonceIncludesNonceHeader() : void {
        $jwk = JWT::createKey();
        $stToken = JWT::sign( $jwk, 'https://example.com/', '12345', [ 'foo' => 'bar' ] );
        $rProtected = $this->protectedHeader( $stToken );
        self::assertSame( '12345', $rProtected[ 'nonce' ] );
    }


    public function testSignWithoutNonceOmitsNonceHeader() : void {
        $jwk = JWT::createKey();
        # A null nonce is used for the inner JWS of a key-rollover request, which
        # RFC 8555 §7.3.5 requires to have no nonce.
        $stToken = JWT::sign( $jwk, 'https://example.com/', null, [ 'foo' => 'bar' ] );
        $rProtected = $this->protectedHeader( $stToken );
        self::assertArrayNotHasKey( 'nonce', $rProtected );
        self::assertSame( 'https://example.com/', $rProtected[ 'url' ] );
        self::assertArrayHasKey( 'jwk', $rProtected );
        self::assertTrue( JWT::isConsistent( $stToken ) );
    }


    /** @return mixed[] */
    private function protectedHeader( string $i_stToken ) : array {
        $r = json_decode( $i_stToken, true );
        self::assertIsArray( $r );
        self::assertIsString( $r[ 'protected' ] );
        return Base64Url::decodeJSON( $r[ 'protected' ] );
    }


}
