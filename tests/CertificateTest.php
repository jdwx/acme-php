<?php


declare( strict_types = 1 );


use JDWX\ACME\Certificate;
use JDWX\ACME\KeyType;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;


#[CoversClass( Certificate::class )]
final class CertificateTest extends TestCase {


    private OpenSSLAsymmetricKey $caKey;

    private OpenSSLCertificate $caCrt;


    public function testBase64Url() : void {
        $pair = $this->makePair( 'test' );
        assert( $pair->crt instanceof OpenSSLCertificate );
        $st = Certificate::toBase64Url( $pair->crt );
        $crt = Certificate::fromBase64Url( $st );
        self::assertTrue( Certificate::verifyKey( $crt, $pair->key ) );
    }


    public function testKeyToString() : void {
        $pair = $this->makePair( 'test' );
        openssl_pkey_export( $pair->key, $st );
        $stActual = trim( $st );
        $stCheck = trim( Certificate::keyToString( $pair->key ) );
        self::assertSame( $stActual, $stCheck );
        $stCheck = trim( Certificate::keyToString( $stActual ) );
        self::assertSame( $stActual, $stCheck );
    }


    public function testMakeKeyForEC() : void {
        /** @noinspection PhpRedundantOptionalArgumentInspection */
        $key = Certificate::makeKey( KeyType::EC );
        $details = openssl_pkey_get_details( $key );
        self::assertIsArray( $details );
        self::assertArrayHasKey( 'ec', $details );
        self::assertArrayHasKey( 'curve_name', $details[ 'ec' ] );
    }


    public function testMakeKeyForRSA() : void {
        $key = Certificate::makeKey( KeyType::RSA );
        $details = openssl_pkey_get_details( $key );
        self::assertIsArray( $details );
        self::assertArrayHasKey( 'rsa', $details );
        self::assertArrayHasKey( 'n', $details[ 'rsa' ] );
    }


    public function testMakePEMForNoCertificate() : void {
        $pair = $this->makePair( 'test' );
        $this->expectException( RuntimeException::class );
        Certificate::makePEM( $pair->key );
    }


    public function testPEMFiles() : void {
        $pair = $this->makePair( 'file-test' );
        $stKeyFile = tempnam( sys_get_temp_dir(), 'key' );
        $stCrtFile = tempnam( sys_get_temp_dir(), 'crt' );
        $stChainFile = tempnam( sys_get_temp_dir(), 'chn' );

        # Try with the cert and chain in separate files.
        Certificate::writeKeyPrivate( $stKeyFile, $pair->key );
        Certificate::writeChain( $stCrtFile, $pair->crt );
        Certificate::writeChain( $stChainFile, $this->caCrt );
        $stPEM = Certificate::makePEMFromFiles( $stKeyFile, $stCrtFile, $stChainFile );
        $pem = Certificate::parsePEM( $stPEM );
        self::assertInstanceOf( OpenSSLAsymmetricKey::class, $pem->key );
        self::assertInstanceOf( OpenSSLCertificate::class, $pem->crt );
        self::assertInstanceOf( OpenSSLCertificate::class, $pem->chn[ 0 ] );
        self::assertCount( 1, $pem->chn );
        self::assertTrue( Certificate::verifyKey( $pem->crt, $pair->key ) );
        self::assertTrue( Certificate::verifyKey( $pair->crt, $pem->key ) );
        unlink( $stCrtFile );
        unlink( $stChainFile );

        # Now try it with both certs in one chain file.
        Certificate::writeChain( $stChainFile, [ $pair->crt, $this->caCrt ] );
        $stPEM = Certificate::makePEMFromFiles( $stKeyFile, null, $stChainFile );
        $pem = Certificate::parsePEM( $stPEM );
        self::assertInstanceOf( OpenSSLAsymmetricKey::class, $pem->key );
        self::assertInstanceOf( OpenSSLCertificate::class, $pem->crt );
        self::assertInstanceOf( OpenSSLCertificate::class, $pem->chn[ 0 ] );
        self::assertCount( 1, $pem->chn );
        self::assertTrue( Certificate::verifyKey( $pem->crt, $pair->key ) );
        self::assertTrue( Certificate::verifyKey( $pair->crt, $pem->key ) );
        unlink( $stChainFile );

        # Now try it with certificates in the wrong order.
        Certificate::writeChain( $stChainFile, [ $this->caCrt, $pair->crt ] );
        $this->expectException( RuntimeException::class );
        Certificate::makePEMFromFiles( $stKeyFile, null, $stChainFile );
    }


    public function testPEMStrings() : void {
        $pair = $this->makePair( 'test' );
        $st = Certificate::makePEM( $pair->key, $pair->crt, $this->caCrt );
        $pem = Certificate::parsePEM( $st );
        self::assertInstanceOf( OpenSSLAsymmetricKey::class, $pem->key );
        self::assertInstanceOf( OpenSSLCertificate::class, $pem->crt );
        self::assertInstanceOf( OpenSSLCertificate::class, $pem->chn[ 0 ] );
        self::assertCount( 1, $pem->chn );
        self::assertTrue( Certificate::verifyKey( $pem->crt, $pair->key ) );
        self::assertTrue( Certificate::verifyKey( $pair->crt, $pem->key ) );
    }


    public function testSelfSignedCert() : void {
        $x = $this->makeSelfSignedCert();
        self::assertInstanceOf( OpenSSLAsymmetricKey::class, $x->key );
        self::assertInstanceOf( OpenSSLCertificate::class, $x->crt );
        self::assertTrue( Certificate::verifyKey( $x->crt, $x->key ) );
    }


    public function testToString() : void {
        $pair = $this->makePair( 'test' );
        $stExpected = trim( openssl_x509_export( $pair->crt, $st ) ? $st : '' );
        self::assertSame( $stExpected, trim( Certificate::toString( $pair->crt ) ) );
        self::assertSame( $stExpected, trim( Certificate::toString( $stExpected ) ) );
        self::assertSame( '', Certificate::toString( [] ) );
        $r = [ $pair->crt, $this->caCrt ];
        $stExpected1 = trim( openssl_x509_export( $pair->crt, $st ) ? $st : '' );
        $stExpected2 = trim( openssl_x509_export( $this->caCrt, $st ) ? $st : '' );
        $stExpected = $stExpected1 . "\n" . $stExpected2;
        $stCheck = trim( Certificate::toString( $r ) );
        self::assertSame( $stExpected, $stCheck );
    }


    protected function setup() : void {
        $x = $this->makeSelfSignedCert();
        $this->caKey = $x->key;
        $this->caCrt = $x->crt;
    }


    private function makePair( string $i_stCN ) : stdClass {
        $key = Certificate::makeKey();
        $csr = Certificate::makeCSR( $key, [ $i_stCN ] );
        $crt = $this->sign( $csr );
        $x = new stdClass();
        $x->key = $key;
        $x->crt = $crt;
        return $x;
    }


    private function makeSelfSignedCert() : stdClass {
        $key = Certificate::makeKey();
        $csr = Certificate::makeCSR( $key, [ 'test-ca' ] );
        $crt = Certificate::signCSR( $key, $csr, 2 );
        $x = new stdClass();
        $x->key = $key;
        $x->crt = $crt;
        return $x;
    }


    private function sign( string|OpenSSLCertificateSigningRequest $i_csr ) : OpenSSLCertificate {
        return Certificate::signCSR( $this->caKey, $i_csr, 2 );
    }


}
