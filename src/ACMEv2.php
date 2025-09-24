<?php


declare( strict_types = 1 );
/** @noinspection PhpUnused */


namespace JDWX\ACME;


use InvalidArgumentException;
use JDWX\ACME\Exceptions\AccountDoesNotExistException;
use JDWX\ACME\Exceptions\ACMEException;
use JDWX\ACME\Exceptions\AlreadyRevokedException;
use JDWX\ACME\Exceptions\BadNonceException;
use JDWX\ACME\Exceptions\BadRevocationReason;
use JDWX\ACME\Exceptions\CAAException;
use JDWX\ACME\Exceptions\MalformedException;
use JDWX\ACME\Exceptions\RateLimitException;
use JDWX\ACME\Exceptions\RuntimeException;
use JDWX\ACME\Exceptions\ServerException;
use JDWX\ACME\Exceptions\ServerInternalException;
use JDWX\ACME\Exceptions\UnauthorizedException;
use JDWX\Json\Json;
use JDWX\JsonApiClient\HttpClient;
use JDWX\JsonApiClient\Response;
use Jose\Component\Core\JWK;


final class ACMEv2 {


    /** @const list<string> */
    private const array ERROR_PREFIXES = [
        'urn:ietf:params:acme:error:',
        'urn:acme:error:',
    ];


    public const string LE_STAGING_URL    = 'https://acme-staging-v02.api.letsencrypt.org/directory';

    public const string LE_PRODUCTION_URL = 'https://acme-v02.api.letsencrypt.org/directory';


    private ?string $nstNextNonce = null;

    /** @var mixed[]|null */
    private ?array $nrDirectory = null;

    private HttpClient $client;


    public function __construct( private readonly string $stDirectoryURL ) {
        $this->client = HttpClient::withGuzzle( '' );
    }


    public static function grabBody( string $i_stResponse ) : string {
        $r = explode( "\r\n", $i_stResponse );
        $stBody = '';
        $bBody = false;
        foreach ( $r as $stLine ) {
            if ( $bBody ) {
                $stBody .= $stLine;
            }
            if ( '' === $stLine ) {
                $bBody = true;
            }
        }
        return $stBody;
    }


    public static function grabBodyCertificate( Response $i_rsp ) : string {
        if ( ! $i_rsp->isContentTypeLoose( 'application', 'pem-certificate-chain' ) ) {
            throw new InvalidArgumentException( 'Response is not a certificate: ' . $i_rsp );
        }
        return $i_rsp->body();
    }


    /** @return array<string, mixed> */
    public static function grabBodyJSON( Response $i_rsp ) : array {
        if ( ! $i_rsp->isContentTypeSubtype( 'json' ) ) {
            throw new InvalidArgumentException( 'Response is not JSON: ' . $i_rsp );
        }
        return Json::expectDict( $i_rsp->json() );
    }


    public static function grabHeader( string $i_stResponse, string $i_stHeader ) : ?string {
        $r = explode( "\r\n", $i_stResponse );
        foreach ( $r as $stLine ) {
            if ( trim( $stLine ) === '' ) {
                return null;
            }
            if ( str_starts_with( $stLine, 'HTTP/' ) ) {
                continue;
            }
            $s = explode( ':', $stLine, 2 );
            if ( 2 !== count( $s ) ) {
                return null;
            }
            $stHeader = strtolower( trim( $s[ 0 ] ) );
            if ( $stHeader !== $i_stHeader ) {
                continue;
            }
            return trim( $s[ 1 ] );
        }
        return null;
    }


    /** @param array<string, mixed> $i_rError */
    public static function isError( array $i_rError ) : bool {
        if ( ! array_key_exists( 'type', $i_rError ) ) {
            return false;
        }
        if ( ! is_string( $i_rError[ 'type' ] ) ) {
            return false;
        }
        foreach ( self::ERROR_PREFIXES as $stPrefix ) {
            if ( str_starts_with( $i_rError[ 'type' ], $stPrefix ) ) {
                return true;
            }
        }
        return false;
    }


    public static function production() : ACMEv2 {
        return new ACMEv2( self::LE_PRODUCTION_URL );
    }


    public static function revocationReasonStringToCode( string $i_stReason ) : int {
        $st = strtolower( $i_stReason );
        $st = str_replace( [ '-', ' ' ], '', $st );
        /** @noinspection SpellCheckingInspection */
        return match ( $st ) {
            'unspecified', '0' => 0,
            'keycompromise', '1' => 1,
            'cacompromise', '2' => 2,
            'affiliationchanged', '3' => 3,
            'superseded', '4' => 4,
            'cessationofoperation', '5' => 5,
            'certificatehold', '6' => 6,
            'removefromcrl', '8' => 8,
            'privilegewithdrawn', '9' => 9,
            'aacompromise', '10' => 10,
            default => throw new RuntimeException( "Unknown revocation reason: {$i_stReason}" ),
        };
    }


    public static function staging() : ACMEv2 {
        return new ACMEv2( self::LE_STAGING_URL );
    }


    /** @param Response $i_rsp */
    private static function errorCheck( Response $i_rsp ) : void {
        if ( $i_rsp->isSuccess() ) {
            return;
        }
        if ( ! $i_rsp->isContentTypeSubtype( 'json' ) ) {
            throw new ServerException( 'Non-JSON HTTP error: ' . $i_rsp );
        }
        $json = Json::expectDict( $i_rsp->json() );
        if ( ! self::isError( $json ) ) {
            throw new ServerException( 'Non-ACME server error: ' . $i_rsp );
        }
        $stType = $json[ 'type' ];
        assert( is_string( $stType ) );
        $stType = self::stripError( $stType );
        $stDetail = $json[ 'detail' ] ?? $i_rsp->body();
        assert( is_string( $stDetail ) );
        if ( 'rateLimited' === $stType ) {
            $nstRetry = $i_rsp->getOneHeader( 'retry-after' );
            throw new RateLimitException( $stDetail, ntmRetryAfter: $nstRetry );
        }
        throw match ( $stType ) {
            'accountDoesNotExist' => new AccountDoesNotExistException( $stDetail ),
            'alreadyRevoked' => new AlreadyRevokedException( $stDetail ),
            'badNonce' => new BadNonceException( $stDetail ),
            'badRevocationReason' => new BadRevocationReason( $stDetail ),
            'caa' => new CAAException( $stDetail ),
            'malformed' => new MalformedException( $stDetail ),
            'serverInternal' => new ServerInternalException( $stDetail ),
            'unauthorized' => new UnauthorizedException( $stDetail ),
            default => new ACMEException( $stType, $stDetail ),
        };
    }


    private static function stripError( string $i_stError ) : string {
        foreach ( self::ERROR_PREFIXES as $stPrefix ) {
            if ( str_starts_with( $i_stError, $stPrefix ) ) {
                return substr( $i_stError, strlen( $stPrefix ) );
            }
        }
        return $i_stError;
    }


    /** @return mixed[] */
    public function directory() : array {
        if ( ! isset( $this->nrDirectory ) ) {
            $this->nrDirectory = Json::expectDict( $this->get( $this->stDirectoryURL )->json() );
        }
        return $this->nrDirectory;
    }


    public function get( string $i_stURL ) : Response {
        return $this->request( 'GET', $i_stURL );
    }


    public function getEndpoint( string $i_stKey ) : string {
        $rDirectory = $this->directory();
        if ( ! array_key_exists( $i_stKey, $rDirectory ) ) {
            throw new RuntimeException( "No endpoint for {$i_stKey}" );
        }
        $st = $rDirectory[ $i_stKey ];
        assert( is_string( $st ) );
        return $st;
    }


    public function newNonce() : string {
        $stURL = $this->getEndpoint( 'newNonce' );
        $rsp = $this->client->get( $stURL );
        $nstNonce = $rsp->getOneHeader( 'replay-nonce' );
        if ( ! is_string( $nstNonce ) ) {
            throw new ServerException( 'No nonce in response: ' . $rsp );
        }
        return $nstNonce;
    }


    public function post( string $i_stURL, string $i_stBody, string $i_stContentType ) : Response {
        return $this->request( 'POST', $i_stURL, $i_stBody, [
            'Content-Type' => $i_stContentType,
        ] );
    }


    /** @param mixed[]|null $i_nrPayload */
    public function postSigned( JWK $i_jwk, string $i_stURL, ?array $i_nrPayload, ?string $i_kid = null ) : Response {
        $stNonce = $this->_getNonce();
        $stBody = JWT::sign( $i_jwk, $i_stURL, $stNonce, $i_nrPayload, $i_kid );
        return $this->post( $i_stURL, $stBody, 'application/jose+json' );
    }


    private function _getNonce() : string {
        if ( ! is_string( $this->nstNextNonce ) ) {
            return $this->newNonce();
        }
        $st = $this->nstNextNonce;
        $this->nstNextNonce = null;
        return $st;
    }


    /**
     * @param string $i_stMethod
     * @param string $i_stURL
     * @param string|null $i_nstBody
     * @param array<string, string> $i_rHeaders
     * @return Response
     */
    private function request( string  $i_stMethod, string $i_stURL,
                              ?string $i_nstBody = null, array $i_rHeaders = [] ) : Response {
        $i_rHeaders[ 'User-Agent' ] = 'JDWX/ACME';
        $rsp = $this->client->request( $i_stMethod, $i_stURL, $i_nstBody, $i_rHeaders, true );
        self::errorCheck( $rsp );
        $nstNonce = $rsp->getOneHeader( 'replay-nonce' );
        if ( is_string( $nstNonce ) ) {
            $this->nstNextNonce = $nstNonce;
        }
        return $rsp;
    }


}

