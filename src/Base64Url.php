<?php


declare( strict_types = 1 );


namespace JDWX\ACME;


use JDWX\Json\Json;
use RuntimeException;


class Base64Url {


    public static function decode( string $i_stData ) : string {
        $bst = base64_decode( str_replace( [ '-', '_' ], [ '+', '/' ], $i_stData ), true );
        if ( is_string( $bst ) ) {
            return $bst;
        }
        $stExcerpt = substr( $i_stData, 0, 20 );
        throw new RuntimeException( "Failed to decode base64url data: {$stExcerpt}" );
    }


    /** @return mixed[] */
    public static function decodeJSON( string $i_stData ) : array {
        return Json::decodeDict( self::decode( $i_stData ) );
    }


    public static function encode( string $i_stData ) : string {
        return str_replace( [ '+', '/', '=' ], [ '-', '_', '' ], base64_encode( $i_stData ) );
    }


    /** @param mixed[] $i_rData */
    public static function encodeJson( array $i_rData ) : string {
        return self::encode( Json::encode( $i_rData ) );
    }


}
