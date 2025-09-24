<?php


declare( strict_types = 1 );


use JDWX\ACME\Base64Url;
use PHPUnit\Framework\TestCase;


class Base64UrlTest extends TestCase {


    public function testEncode() : void {
        $st = 'Hello, world!';
        $stEncoded = Base64Url::encode( $st );
        /** @noinspection SpellCheckingInspection */
        self::assertEquals( 'SGVsbG8sIHdvcmxkIQ', $stEncoded );
        $stDecoded = Base64Url::decode( $stEncoded );
        self::assertEquals( $st, $stDecoded );
    }


    public function testEncodeJSON() : void {
        $r = [ 'Hello' => 'world' ];
        $stEncoded = Base64Url::encodeJson( $r );
        /** @noinspection SpellCheckingInspection */
        self::assertEquals( 'eyJIZWxsbyI6IndvcmxkIn0', $stEncoded );
        $rDecoded = Base64Url::decodeJSON( $stEncoded );
        self::assertEquals( $r, $rDecoded );
    }


}
