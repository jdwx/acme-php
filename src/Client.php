<?php


declare( strict_types = 1 );


namespace JDWX\ACME;


use JDWX\Json\Json;
use JDWX\JsonApiClient\Response;
use JDWX\Result\Result;
use Jose\Component\Core\JWK;
use RuntimeException;


class Client {


    private ?string $kid = null;


    public function __construct( private readonly JWK $jwk, private readonly ACMEv2 $acme ) {}


    /** @return mixed[] */
    public function account( string $i_stAccountURL ) : array {
        $this->kid = $i_stAccountURL;
        return Json::expectDict( $this->postSigned( $i_stAccountURL )->json() );
    }


    /** @return list<mixed[]> */
    public function authorizations( Order $i_order ) : array {
        if ( ! $i_order->hasAuthorizations() ) {
            throw new RuntimeException( 'No authorization URLs in order.' );
        }
        $rAuths = [];
        foreach ( $i_order->getAuthorizationURLs() as $stURL ) {
            $x = $this->acme->get( $stURL );
            $x = ACMEv2::grabBodyJSON( $x );
            $rAuths[] = $x;
        }
        return $rAuths;
    }


    /** @return list<mixed[]> */
    public function authorizationsByName( Order $i_order, string $i_stName ) : array {
        $rAuths = [];
        $bWildcard = false;
        if ( str_starts_with( $i_stName, '*.' ) ) {
            $i_stName = substr( $i_stName, 2 );
            $bWildcard = true;
        }
        foreach ( $this->authorizations( $i_order ) as $rAuth ) {
            if ( ! array_key_exists( 'identifier', $rAuth ) ) {
                throw new RuntimeException(
                    'No identifier in authorization: ' . Json::encode( $rAuth )
                );
            }
            if ( $rAuth[ 'identifier' ][ 'value' ] !== $i_stName ) {
                continue;
            }
            $bWildcardCheck = $rAuth[ 'wildcard' ] ?? false;
            if ( $bWildcard != $bWildcardCheck ) {
                continue;
            }
            $rAuths[] = $rAuth;
        }
        return $rAuths;
    }


    public function certificate( Order $i_order ) : string {
        if ( ! $i_order->hasCertificate() ) {
            throw new RuntimeException( 'No certificate URL.' );
        }
        $stURL = $i_order->getCertificateURLEx();
        $rsp = $this->acme->get( $stURL );
        $stCertificate = ACMEv2::grabBodyCertificate( $rsp );
        if ( Certificate::isValid( $stCertificate ) ) {
            return $stCertificate;
        }
        throw new RuntimeException( 'Invalid certificate: ' . $stCertificate );
    }


    /** @return mixed[] */
    public function checkChallenge( Order $i_order, string $i_stName, string $i_stChallenge ) : array {
        $rChallenge = $this->getChallenge( $i_order, $i_stName, $i_stChallenge );
        $stURL = $rChallenge[ 'url' ];
        assert( is_string( $stURL ) );
        $x = $this->acme->get( $stURL );
        return ACMEv2::grabBodyJSON( $x );
    }


    /** @return mixed[] */
    public function directory() : array {
        return $this->acme->directory();
    }


    public function finalize( Order $i_order, string $i_csr ) : Order {
        if ( ! $i_order->isReady() ) {
            $stStatus = $i_order->getStatus();
            throw new RuntimeException( "Order status is {$stStatus} not ready" );
        }
        $stURL = $i_order->getFinalizeURLEx();
        $rData = [ 'csr' => Certificate::exportCSR( $i_csr ) ];
        $stResponse = $this->postSigned( $stURL, $rData );
        return new Order( ACMEv2::grabBodyJSON( $stResponse ), $i_order->name() );
    }


    /** @return mixed[] */
    public function getChallenge( Order $i_order, string $i_stName, string $i_stChallenge ) : array {
        foreach ( $this->authorizationsByName( $i_order, $i_stName ) as $rAuth ) {
            assert( is_iterable( $rAuth[ 'challenges' ] ) );
            foreach ( $rAuth[ 'challenges' ] as $rChallenge ) {
                assert( is_array( $rChallenge ) );
                if ( $rChallenge[ 'type' ] !== $i_stChallenge ) {
                    continue;
                }
                return $rChallenge;
            }
        }
        throw new RuntimeException( "No authorization {$i_stChallenge} for {$i_stName}" );
    }


    public function keyAuthorization( string $i_stToken ) : string {
        return $i_stToken . '.' . $this->jwk->thumbprint( 'sha256' );

    }


    public function keyAuthorizationHashed( string $i_stToken ) : string {
        return Base64Url::encode( hash( 'sha256', $this->keyAuthorization( $i_stToken ), true ) );
    }


    public function newAccount( string $i_stContact ) : string {
        $stURL = $this->acme->getEndpoint( 'newAccount' );
        $rData = [
            'contact' => [ "mailto:{$i_stContact}" ],
            'termsOfServiceAgreed' => true,
        ];
        $rsp = $this->postSignedNoKid( $stURL, $rData );
        $nstLocation = $rsp->getOneHeader( 'location' );
        if ( null === $nstLocation ) {
            throw new RuntimeException( 'No location header in response: ' . $rsp );
        }
        $this->kid = $nstLocation;
        return $nstLocation;
    }


    /**
     * @param list<string>|string $i_names
     * @return mixed[]
     */
    public function newOrder( string|array $i_names ) : array {
        if ( is_string( $i_names ) ) {
            $i_names = [ $i_names ];
        }
        $stURL = $this->acme->getEndpoint( 'newOrder' );
        $rIdentifiers = [];
        foreach ( $i_names as $stName ) {
            $rIdentifiers[] = [ 'type' => 'dns', 'value' => $stName ];
        }
        $rData = [ 'identifiers' => $rIdentifiers ];
        $rsp = $this->postSigned( $stURL, $rData );
        $stLocation = $rsp->getOneHeaderEx( 'location' );
        $rBody = Json::expectDict( $rsp->json() );
        $rBody[ 'location' ] = $stLocation;
        return $rBody;
    }


    public function order( string|Order $i_stURL, ?string $i_nstName = null ) : Order {
        if ( $i_stURL instanceof Order ) {
            if ( ! $i_stURL->hasLocation() ) {
                return $i_stURL;
            }
            $i_nstName = $i_stURL->name() ?? $i_nstName;
            $i_stURL = $i_stURL->locationEx();
        }
        return new Order( $this->postSignedJSON( $i_stURL ), $i_nstName );
    }


    public function revoke( Order $i_order, int $i_uReason = 0 ) : Response {
        $stURL = $this->acme->getEndpoint( 'revokeCert' );
        $cert = $this->certificate( $i_order );
        $rCerts = Certificate::parseChain( $cert, $i_order->getNames()[ 0 ] );
        if ( 1 !== count( $rCerts ) ) {
            throw new RuntimeException( 'Did not parse one matching certificate.' );
        }
        $st = Certificate::toBase64Url( $rCerts[ 0 ] );
        $rData = [
            'certificate' => $st,
            'reason' => $i_uReason,
        ];

        return $this->postSigned( $stURL, $rData );
    }


    /** @return mixed[] */
    public function updateAccount( string $i_stContact ) : array {
        $rData = [
            'contact' => [ "mailto:{$i_stContact}" ],
        ];
        return $this->postSignedJSON( $this->kid(), $rData );
    }


    /** @return mixed[] */
    public function validate( Order $i_order, string $i_stName, string $i_stChallenge ) : array {
        $rChallenge = $this->getChallenge( $i_order, $i_stName, $i_stChallenge );
        $stURL = $rChallenge[ 'url' ];
        assert( is_string( $stURL ) );
        $x = $this->postSigned( $stURL, [] );
        return ACMEv2::grabBodyJSON( $x );
    }


    /**
     * @return Result<Order>
     *
     * Orders are sometimes return with a location value, which indicates that something is
     * still in progress. This function will poll the order until it no longer has a location
     * or until the maximum number of attempts is reached.
     *
     * This is a helper for simple scripts. It's not for use in asynchronous or
     * high-volume scenarios!
     */
    public function waitOnOrder( Order $i_order, int $i_nIntervalSeconds = 1, int $i_nMaxAttempts = 30 ) : Result {
        for ( $ii = 0 ; $ii < $i_nMaxAttempts ; $ii++ ) {
            if ( ! $i_order->hasLocation() ) {
                return Result::ok( i_xValue: $i_order );
            }
            sleep( $i_nIntervalSeconds );
            $i_order = $this->order( $i_order );
        }
        return Result::err( 'Waiting for order timed out.', i_xValue: $i_order );
    }


    protected function kid() : string {
        if ( null === $this->kid ) {
            throw new RuntimeException( 'No account selected.' );
        }
        return $this->kid;
    }


    /**
     * @param string $i_stURL
     * @param mixed[]|null $i_nrPayload
     * @return Response
     */
    private function postSigned( string $i_stURL, ?array $i_nrPayload = null ) : Response {
        return $this->acme->postSigned( $this->jwk, $i_stURL, $i_nrPayload, $this->kid );
    }


    /**
     * @param string $i_stURL
     * @param mixed[]|null $i_nrPayload
     * @return array<string, mixed>
     */
    private function postSignedJSON( string $i_stURL, ?array $i_nrPayload = null ) : array {
        $stFetch = $this->postSigned( $i_stURL, $i_nrPayload );
        return ACMEv2::grabBodyJSON( $stFetch );
    }


    /**
     * @param string $i_stURL
     * @param mixed[]|null $i_nrPayload
     * @return Response
     */
    private function postSignedNoKid( string $i_stURL, ?array $i_nrPayload = null ) : Response {
        return $this->acme->postSigned( $this->jwk, $i_stURL, $i_nrPayload );
    }


}
