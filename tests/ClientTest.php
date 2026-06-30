<?php


declare( strict_types = 1 );


namespace JDWX\ACME\Tests;


use JDWX\ACME\ACMEv2;
use JDWX\ACME\Base64Url;
use JDWX\ACME\Certificate;
use JDWX\ACME\Client;
use JDWX\ACME\JWT;
use JDWX\ACME\Order;
use JDWX\Json\Json;
use JDWX\JsonApiClient\MockClient;
use JDWX\JsonApiClient\MockStream;
use JDWX\JsonApiClient\Response;
use Jose\Component\Core\JWK;
use Jose\Component\KeyManagement\JWKFactory;
use OpenSSLCertificateSigningRequest;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;


#[CoversClass( Client::class )]
final class ClientTest extends TestCase {


    private const string ACCOUNT_URL  = 'https://acme.test/account/1';

    private const string KEY_CHANGE_URL = 'https://acme.test/key-change';

    private const string REVOKE_URL   = 'https://acme.test/revoke-cert';

    private const string DIRECTORY    = '{'
        . '"newNonce":"https://acme.test/new-nonce",'
        . '"newAccount":"https://acme.test/new-account",'
        . '"keyChange":"' . self::KEY_CHANGE_URL . '",'
        . '"revokeCert":"' . self::REVOKE_URL . '"'
        . '}';


    public function testKeyChangeAdoptsNewKey() : void {
        [ $client, $cli, $jwkOld ] = $this->primedClient();
        $cli->queueResponse( self::makeResponse( 200, '{"status":"valid"}', [
            'content-type' => 'application/json',
            'replay-nonce' => 'nonce-3',
        ] ) );
        # A second response so a follow-up signed request can be inspected.
        $cli->queueResponse( self::makeResponse( 200, '{"status":"valid"}', [
            'content-type' => 'application/json',
        ] ) );

        $jwkNew = JWT::createKey();
        $client->keyChange( $jwkNew );

        # Issue another signed request; it must now be signed with the new key.
        $client->updateAccount( 'new@example.com' );

        $cli->shiftRequest(); # directory GET
        $cli->shiftRequest(); # newAccount POST
        $cli->shiftRequest(); # keyChange POST
        $req = $cli->shiftRequestArray(); # updateAccount POST
        $stBody = $req[ 'body' ];
        self::assertIsString( $stBody );
        self::assertTrue( JWT::verify( $stBody, $jwkNew->toPublic()->jsonSerialize() ) );
        self::assertFalse( JWT::verify( $stBody, $jwkOld->toPublic()->jsonSerialize() ) );
    }


    public function testKeyChangeRequestStructure() : void {
        [ $client, $cli, $jwkOld ] = $this->primedClient();
        $cli->queueResponse( self::makeResponse( 200, '{"status":"valid"}', [
            'content-type' => 'application/json',
            'replay-nonce' => 'nonce-3',
        ] ) );

        $jwkNew = JWT::createKey();
        $rAccount = $client->keyChange( $jwkNew );
        self::assertSame( 'valid', $rAccount[ 'status' ] );

        $cli->shiftRequest(); # directory GET
        $cli->shiftRequest(); # newAccount POST
        $req = $cli->shiftRequestArray(); # keyChange POST
        self::assertSame( 'POST', $req[ 'method' ] );
        self::assertSame( self::KEY_CHANGE_URL, $req[ 'path' ] );

        $stOuter = $req[ 'body' ];
        self::assertIsString( $stOuter );

        # The outer JWS is signed with the old (current) account key and uses a
        # "kid" header rather than an embedded "jwk".
        self::assertTrue( JWT::verify( $stOuter, $jwkOld->toPublic()->jsonSerialize() ) );
        $rOuter = Json::decodeDict( $stOuter );
        $rOuterProtected = Base64Url::decodeJSON( self::str( $rOuter[ 'protected' ] ) );
        self::assertSame( self::ACCOUNT_URL, $rOuterProtected[ 'kid' ] );
        self::assertSame( self::KEY_CHANGE_URL, $rOuterProtected[ 'url' ] );
        self::assertArrayHasKey( 'nonce', $rOuterProtected );
        self::assertArrayNotHasKey( 'jwk', $rOuterProtected );

        # The payload of the outer JWS is the inner JWS.
        $stInner = Base64Url::decode( self::str( $rOuter[ 'payload' ] ) );

        # The inner JWS is signed with the new key, embeds it as "jwk", repeats
        # the URL, and carries no nonce (RFC 8555 §7.3.5).
        self::assertTrue( JWT::verify( $stInner, $jwkNew->toPublic()->jsonSerialize() ) );
        $rInner = Json::decodeDict( $stInner );
        $rInnerProtected = Base64Url::decodeJSON( self::str( $rInner[ 'protected' ] ) );
        self::assertSame( self::KEY_CHANGE_URL, $rInnerProtected[ 'url' ] );
        self::assertSame( $jwkNew->toPublic()->jsonSerialize(), $rInnerProtected[ 'jwk' ] );
        self::assertArrayNotHasKey( 'nonce', $rInnerProtected );
        self::assertArrayNotHasKey( 'kid', $rInnerProtected );

        # The inner payload names the account and the old key being replaced.
        $rInnerPayload = Base64Url::decodeJSON( self::str( $rInner[ 'payload' ] ) );
        self::assertSame( self::ACCOUNT_URL, $rInnerPayload[ 'account' ] );
        self::assertSame( $jwkOld->toPublic()->jsonSerialize(), $rInnerPayload[ 'oldKey' ] );
    }


    public function testRevokeWithAccountKeySignsWithKid() : void {
        [ $client, $cli, $jwkAccount ] = $this->primedClient();
        [ $order, $stCertPem ] = $this->certifiedOrder();
        $cli->queueResponse( self::makeResponse( 200, $stCertPem, [
            'content-type' => 'application/pem-certificate-chain',
        ] ) );
        $cli->queueResponse( self::makeResponse( 200, '', [ 'content-type' => 'application/json' ] ) );

        $client->revoke( $order );

        $cli->shiftRequest(); # directory GET
        $cli->shiftRequest(); # newAccount POST
        $cli->shiftRequest(); # certificate GET
        $req = $cli->shiftRequestArray(); # revoke POST
        self::assertSame( 'POST', $req[ 'method' ] );
        self::assertSame( self::REVOKE_URL, $req[ 'path' ] );
        $stBody = $req[ 'body' ];
        self::assertIsString( $stBody );

        # Default revocation is signed with the account key and identifies the
        # account by "kid" rather than embedding a "jwk" (RFC 8555 §7.6).
        self::assertTrue( JWT::verify( $stBody, $jwkAccount->toPublic()->jsonSerialize() ) );
        $rProtected = Base64Url::decodeJSON( self::str( Json::decodeDict( $stBody )[ 'protected' ] ) );
        self::assertSame( self::ACCOUNT_URL, $rProtected[ 'kid' ] );
        self::assertArrayNotHasKey( 'jwk', $rProtected );
        $rPayload = Base64Url::decodeJSON( self::str( Json::decodeDict( $stBody )[ 'payload' ] ) );
        self::assertArrayHasKey( 'certificate', $rPayload );
        self::assertSame( 0, $rPayload[ 'reason' ] );
    }


    public function testRevokeWithCertificateKeySignsWithJwk() : void {
        [ $client, $cli, $jwkAccount ] = $this->primedClient();
        [ $order, $stCertPem, $stKeyPem ] = $this->certifiedOrder();
        $cli->queueResponse( self::makeResponse( 200, $stCertPem, [
            'content-type' => 'application/pem-certificate-chain',
        ] ) );
        $cli->queueResponse( self::makeResponse( 200, '', [ 'content-type' => 'application/json' ] ) );

        # Revoke for key compromise, signing with the certificate's own key.
        $client->revoke( $order, 1, $stKeyPem );

        $cli->shiftRequest(); # directory GET
        $cli->shiftRequest(); # newAccount POST
        $cli->shiftRequest(); # certificate GET
        $req = $cli->shiftRequestArray(); # revoke POST
        $stBody = $req[ 'body' ];
        self::assertIsString( $stBody );

        # The request must be signed with the certificate key and embed it as a
        # "jwk" header, never the account key nor a "kid" (RFC 8555 §7.6).
        $jwkCert = JWKFactory::createFromKey( $stKeyPem );
        self::assertTrue( JWT::verify( $stBody, $jwkCert->toPublic()->jsonSerialize() ) );
        self::assertFalse( JWT::verify( $stBody, $jwkAccount->toPublic()->jsonSerialize() ) );
        $rProtected = Base64Url::decodeJSON( self::str( Json::decodeDict( $stBody )[ 'protected' ] ) );
        self::assertArrayHasKey( 'jwk', $rProtected );
        self::assertArrayNotHasKey( 'kid', $rProtected );
        $rPayload = Base64Url::decodeJSON( self::str( Json::decodeDict( $stBody )[ 'payload' ] ) );
        self::assertSame( 1, $rPayload[ 'reason' ] );
    }


    /**
     * Build a "valid" order for revoke.test together with a self-signed
     * certificate (CN via SAN) and the PEM of the key that signed it.
     *
     * @return array{Order, string, string} [ order, certificate PEM, key PEM ]
     */
    private function certifiedOrder() : array {
        # Put the name in the subject CN rather than a SAN: openssl_csr_sign()
        # does not copy CSR extensions, so a SAN would be dropped and the
        # certificate would carry no name for parseChain() to match.
        $key = Certificate::makeKeyEC();
        $csr = openssl_csr_new( [ 'commonName' => 'revoke.test' ], $key, [ 'digest_alg' => 'sha384' ] );
        self::assertInstanceOf( OpenSSLCertificateSigningRequest::class, $csr );
        $crt = Certificate::signCSR( $key, $csr, 2 );
        $order = new Order( [
            'status' => 'valid',
            'identifiers' => [ [ 'type' => 'dns', 'value' => 'revoke.test' ] ],
            'certificate' => 'https://acme.test/cert/1',
        ], 'revoke.test' );
        return [ $order, Certificate::toString( $crt ), Certificate::keyToString( $key ) ];
    }


    /** @param array<string, string> $i_rHeaders */
    private static function makeResponse( int $i_uStatus, string $i_stBody, array $i_rHeaders = [] ) : Response {
        $rHeaders = [];
        foreach ( $i_rHeaders as $stName => $stValue ) {
            $rHeaders[ $stName ] = [ $stValue ];
        }
        return new Response( $i_uStatus, $rHeaders, new MockStream( $i_stBody ) );
    }


    private static function str( mixed $i_x ) : string {
        self::assertIsString( $i_x );
        return $i_x;
    }


    /**
     * Build a client that has already created an account, leaving a cached
     * nonce ready for the next request.
     *
     * @return array{Client, MockClient, JWK}
     */
    private function primedClient() : array {
        $cli = new MockClient( null );
        $cli->queueResponse( self::makeResponse( 200, self::DIRECTORY, [
            'content-type' => 'application/json',
            'replay-nonce' => 'nonce-1',
        ] ) );
        $cli->queueResponse( self::makeResponse( 200, '{}', [
            'content-type' => 'application/json',
            'location' => self::ACCOUNT_URL,
            'replay-nonce' => 'nonce-2',
        ] ) );
        $acme = new ACMEv2( 'https://acme.test/directory', $cli );
        $jwk = JWT::createKey();
        $client = new Client( $jwk, $acme );
        $client->newAccount( 'test@example.com' );
        return [ $client, $cli, $jwk ];
    }


}
