<?php


declare( strict_types = 1 );


namespace JDWX\ACME;


use JDWX\Json\Json;
use JDWX\Strict\TypeIs;
use Jose\Component\Core\AlgorithmManager;
use Jose\Component\Core\JWK;
use Jose\Component\KeyManagement\JWKFactory;
use Jose\Component\Signature\Algorithm\ES384;
use Jose\Component\Signature\JWSBuilder;
use Jose\Component\Signature\JWSVerifier;
use Jose\Component\Signature\Serializer\CompactSerializer;
use Jose\Component\Signature\Serializer\JWSSerializerManager;
use RuntimeException;


final class JWT {


    public static function createKey() : JWK {
        return JWKFactory::createECKey( 'P-384' );
    }


    public static function getOrCreateKey( string $i_stPrivateKeyPath ) : JWK {
        if ( ! file_exists( $i_stPrivateKeyPath ) ) {
            Certificate::writeKeyPrivate( $i_stPrivateKeyPath, Certificate::makeKeyEC() );
        }
        return JWKFactory::createFromKeyFile( $i_stPrivateKeyPath );
    }


    /**
     * @param string $i_stContent
     * @return bool True if the content is correctly formed and signed by the key it
     *              claims to be signed by.
     * @throws \JsonException
     */
    public static function isConsistent( string $i_stContent ) : bool {
        $r = Json::decodeDict( $i_stContent );
        if ( ! isset( $r[ 'protected' ] ) ) {
            throw new RuntimeException( 'No protected header' );
        }
        $stProtected = $r[ 'protected' ];
        $rProtected = Base64Url::decodeJSON( TypeIs::string( $stProtected ) );
        $jwk = $rProtected[ 'jwk' ];
        if ( ! is_array( $jwk ) ) {
            throw new RuntimeException( 'No JWK in protected header' );
        }
        return self::verify( $i_stContent, $jwk );
    }


    /** @param mixed[]|null $i_nrPayload */
    public static function sign( JWK    $i_jwk, string $i_stURL, string $i_stNonce,
                                 ?array $i_nrPayload = null, ?string $i_kid = null ) : string {
        $rProtected = [
            'alg' => 'ES384',
            'nonce' => $i_stNonce,
            'url' => $i_stURL,
        ];
        if ( is_string( $i_kid ) ) {
            $rProtected[ 'kid' ] = $i_kid;
        } else {
            $rProtected[ 'jwk' ] = $i_jwk->toPublic()->jsonSerialize();
        }
        if ( is_array( $i_nrPayload ) ) {
            if ( $i_nrPayload === [] ) {
                $stPayload = '{}';
            } else {
                $stPayload = Json::encode( $i_nrPayload );
            }
        } else {
            $stPayload = '';
        }

        $sam = new AlgorithmManager( [ new ES384() ] );
        $jws = new JWSBuilder( $sam );
        $jws = $jws->create()->withPayload( $stPayload )->addSignature( $i_jwk, $rProtected )->build();
        $serializer = new CompactSerializer();
        $stToken = $serializer->serialize( $jws, 0 );
        $r = explode( '.', $stToken );
        $r = [
            'protected' => $r[ 0 ],
            'payload' => $r[ 1 ],
            'signature' => $r[ 2 ],
        ];
        return Json::encode( $r );
    }


    /** @param mixed[]|JWK $i_jwk */
    public static function verify( string $i_stContent, array|JWK $i_jwk ) : bool {
        if ( is_array( $i_jwk ) ) {
            $i_jwk = new JWK( $i_jwk );
        }
        $r = Json::decodeDict( $i_stContent );
        $stProtected = $r[ 'protected' ];
        assert( is_string( $stProtected ) );
        $stPayload = $r[ 'payload' ];
        assert( is_string( $stPayload ) );
        $stSignature = $r[ 'signature' ];
        assert( is_string( $stSignature ) );
        $stToken = $stProtected . '.' . $stPayload . '.' . $stSignature;

        $algorithmManager = new AlgorithmManager( [ new ES384() ] );
        $jwsVerifier = new JWSVerifier( $algorithmManager );
        $serializeManager = new JWSSerializerManager( [ new CompactSerializer() ] );
        $jws = $serializeManager->unserialize( $stToken );
        return $jwsVerifier->verifyWithKey( $jws, $i_jwk, 0 );
    }


}
