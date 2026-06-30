<?php


declare( strict_types = 1 );


namespace JDWX\ACME\Tests;


use JDWX\ACME\Base64Url;
use JDWX\ACME\JWT;
use Jose\Component\KeyManagement\JWKFactory;
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


    public function testSignWithAccountKeyUsesES384() : void {
        # Account keys created by this library are EC P-384; signing must stay
        # on ES384 so the existing account-key behavior is unchanged.
        $jwk = JWT::createKey();
        $stToken = JWT::sign( $jwk, 'https://example.com/', '12345', [ 'foo' => 'bar' ] );
        self::assertSame( 'ES384', $this->protectedHeader( $stToken )[ 'alg' ] );
    }


    public function testSignWithEcP256KeyUsesES256() : void {
        # A certificate key offered for revocation may be on a different curve;
        # the algorithm must follow the key (RFC 8555 §7.6).
        $jwk = JWKFactory::createECKey( 'P-256' );
        $stToken = JWT::sign( $jwk, 'https://example.com/', '12345', [ 'foo' => 'bar' ] );
        self::assertSame( 'ES256', $this->protectedHeader( $stToken )[ 'alg' ] );
        self::assertTrue( JWT::isConsistent( $stToken ) );
    }


    public function testSignWithRsaKeyUsesRS256() : void {
        # RSA certificate keys are common, so revocation signed with one must
        # produce a verifiable RS256 JWS rather than failing on a fixed ES384.
        $jwk = JWKFactory::createRSAKey( 2048 );
        $stToken = JWT::sign( $jwk, 'https://example.com/', '12345', [ 'foo' => 'bar' ] );
        self::assertSame( 'RS256', $this->protectedHeader( $stToken )[ 'alg' ] );
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
