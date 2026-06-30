<?php


declare( strict_types = 1 );


namespace JDWX\ACME\Tests;


use JDWX\ACME\ACMEv2;
use JDWX\ACME\Exceptions\InvalidArgumentException;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;


#[CoversClass( ACMEv2::class )]
final class ACMEv2Test extends TestCase {


    public function testRevocationReasonStringToCode() : void {
        self::assertSame( 0, ACMEv2::revocationReasonStringToCode( 'unspecified' ) );
        self::assertSame( 1, ACMEv2::revocationReasonStringToCode( 'keycompromise' ) );
        self::assertSame( 2, ACMEv2::revocationReasonStringToCode( 'cacompromise' ) );
        self::assertSame( 3, ACMEv2::revocationReasonStringToCode( 'affiliationchanged' ) );
        self::assertSame( 4, ACMEv2::revocationReasonStringToCode( 'superseded' ) );
        self::assertSame( 5, ACMEv2::revocationReasonStringToCode( 'cessationofoperation' ) );
        self::assertSame( 6, ACMEv2::revocationReasonStringToCode( 'certificatehold' ) );
        self::assertSame( 8, ACMEv2::revocationReasonStringToCode( 'removefromcrl' ) );
        self::assertSame( 9, ACMEv2::revocationReasonStringToCode( 'privilegewithdrawn' ) );
        self::assertSame( 10, ACMEv2::revocationReasonStringToCode( 'aacompromise' ) );
    }


    public function testRevocationReasonStringToCodeForBadCode() : void {
        $this->expectException( InvalidArgumentException::class );
        ACMEv2::revocationReasonStringToCode( 'badcode' );
    }


}
