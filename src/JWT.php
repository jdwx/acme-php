<?php


declare( strict_types = 1 );


namespace JDWX\ACME;


use JDWX\Json\Json;
use JDWX\Strict\TypeIs;
use Jose\Component\Core\AlgorithmManager;
use Jose\Component\Core\JWK;
use Jose\Component\KeyManagement\JWKFactory;
use Jose\Component\Signature\Algorithm\ES256;
use Jose\Component\Signature\Algorithm\ES384;
use Jose\Component\Signature\Algorithm\ES512;
use Jose\Component\Signature\Algorithm\RS256;
use Jose\Component\Signature\Algorithm\SignatureAlgorithm;
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


    /**
     * Select the JWS signature algorithm appropriate for a key.
     *
     * ACME account keys created by this library are always EC P-384 (ES384),
     * but a certificate key supplied for revocation (RFC 8555 §7.6) may be RSA
     * or a different EC curve, so the algorithm must follow the key rather than
     * being fixed.
     */
    private static function algorithmFor( JWK $i_jwk ) : SignatureAlgorithm {
        $stKeyType = $i_jwk->has( 'kty' ) ? TypeIs::string( $i_jwk->get( 'kty' ) ) : '';
        if ( 'RSA' === $stKeyType ) {
            return new RS256();
        }
        if ( 'EC' === $stKeyType ) {
            $stCurve = $i_jwk->has( 'crv' ) ? TypeIs::string( $i_jwk->get( 'crv' ) ) : '';
            return match ( $stCurve ) {
                'P-256' => new ES256(),
                'P-384' => new ES384(),
                'P-521' => new ES512(),
                default => throw new RuntimeException( "Unsupported EC curve for signing: {$stCurve}" ),
            };
        }
        throw new RuntimeException( "Unsupported key type for signing: {$stKeyType}" );
    }


    /**
     * @param mixed[]|null $i_nrPayload
     *
     * A null nonce produces a JWS without a "nonce" header parameter. This is
     * required for the inner JWS of a key-rollover request (RFC 8555 §7.3.5);
     * ordinary ACME requests must always supply a nonce.
     */
    public static function sign( JWK    $i_jwk, string $i_stURL, ?string $i_nstNonce,
                                 ?array $i_nrPayload = null, ?string $i_kid = null ) : string {
        $alg = self::algorithmFor( $i_jwk );
        $rProtected = [ 'alg' => $alg->name() ];
        if ( is_string( $i_nstNonce ) ) {
            $rProtected[ 'nonce' ] = $i_nstNonce;
        }
        $rProtected[ 'url' ] = $i_stURL;
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

        $sam = new AlgorithmManager( [ $alg ] );
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

        $algorithmManager = new AlgorithmManager( [ self::algorithmFor( $i_jwk ) ] );
        $jwsVerifier = new JWSVerifier( $algorithmManager );
        $serializeManager = new JWSSerializerManager( [ new CompactSerializer() ] );
        $jws = $serializeManager->unserialize( $stToken );
        return $jwsVerifier->verifyWithKey( $jws, $i_jwk, 0 );
    }


}
