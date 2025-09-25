<?php /** @noinspection PhpUnused */


declare( strict_types = 1 );


namespace JDWX\ACME;


use JDWX\ACME\Exceptions\RuntimeException;
use JDWX\Strict\TypeIs;


readonly class Order {


    /** @param mixed[] $rOrder */
    public function __construct( private array $rOrder, private ?string $nstName = null ) {}


    /** @return list<string> */
    public function getAuthorizationURLs() : array {
        /** @phpstan-ignore-next-line */
        return $this->rOrder[ 'authorizations' ];
    }


    public function getCertificateURL() : ?string {
        $nst = $this->rOrder[ 'certificate' ] ?? null;
        assert( is_string( $nst ) || is_null( $nst ) );
        return $nst;
    }


    public function getCertificateURLEx() : string {
        $nst = $this->getCertificateURL();
        if ( is_string( $nst ) ) {
            return $nst;
        }
        throw new RuntimeException( 'No certificate URL.' );
    }


    public function getFinalizeURL() : ?string {
        $nst = $this->rOrder[ 'finalize' ] ?? null;
        assert( is_string( $nst ) || is_null( $nst ) );
        return $nst;
    }


    public function getFinalizeURLEx() : string {
        $nst = $this->getFinalizeURL();
        if ( is_string( $nst ) ) {
            return $nst;
        }
        throw new RuntimeException( 'No finalize URL.' );
    }


    /** @return array<string, mixed[]> */
    public function getIdentifiers() : array {
        /** @phpstan-ignore-next-line */
        return $this->rOrder[ 'identifiers' ];
    }


    /** @return list<string> */
    public function getNames() : array {
        $rNames = [];
        foreach ( $this->getIdentifiers() as $rIdentifier ) {
            $st = $rIdentifier[ 'value' ];
            assert( is_string( $st ) );
            $rNames[] = $st;
        }
        return $rNames;
    }


    public function getStatus() : string {
        $st = $this->rOrder[ 'status' ];
        assert( is_string( $st ) );
        return strtolower( trim( $st ) );
    }


    public function hasAuthorizations() : bool {
        return array_key_exists( 'authorizations', $this->rOrder );
    }


    public function hasCertificate() : bool {
        return array_key_exists( 'certificate', $this->rOrder );
    }


    public function hasFinalize() : bool {
        return array_key_exists( 'finalize', $this->rOrder );
    }


    public function hasLocation() : bool {
        return array_key_exists( 'location', $this->rOrder );
    }


    public function hasStatus() : bool {
        return array_key_exists( 'status', $this->rOrder );
    }


    public function isError() : bool {
        return ACMEv2::isError( $this->rOrder );
    }


    public function isExpired() : bool {
        $st = $this->rOrder[ 'expires' ];
        assert( is_string( $st ) );
        return strtotime( $st ) < time();
    }


    public function isReady() : bool {
        return $this->getStatus() === 'ready';
    }


    public function location() : ?string {
        return TypeIs::stringOrNull( $this->rOrder[ 'location' ] ?? null );
    }


    public function locationEx() : string {
        $nst = $this->location();
        if ( is_string( $nst ) ) {
            return $nst;
        }
        throw new RuntimeException( 'Order has no location.' );
    }


    public function name() : ?string {
        return $this->nstName;
    }


    public function nameEx() : string {
        $nst = $this->name();
        if ( is_string( $nst ) ) {
            return $nst;
        }
        throw new RuntimeException( 'Order has no name.' );
    }


}
