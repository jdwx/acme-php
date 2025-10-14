<?php /** @noinspection PhpUnused */


declare( strict_types = 1 );


namespace JDWX\ACME;


use OpenSSLAsymmetricKey;
use OpenSSLCertificate;
use OpenSSLCertificateSigningRequest;
use RuntimeException;
use stdClass;


final class Certificate {


    /** @param OpenSSLCertificate[] $i_certs */
    public static function byName( array $i_certs, string $i_stName ) : ?OpenSSLCertificate {
        $rAllNames = [];
        foreach ( $i_certs as $crt ) {
            $rNames = self::getNames( $crt );
            if ( in_array( $i_stName, $rNames ) ) {
                return $crt;
            }
            foreach ( $rNames as $stName ) {
                if ( str_starts_with( $stName, '*.' ) ) {
                    $stWild = substr( $stName, 1 );
                    if ( str_ends_with( $i_stName, $stWild ) ) {
                        return $crt;
                    }
                }
            }
            $rAllNames = array_merge( $rAllNames, $rNames );
        }
        return null;
    }


    /** @param list<OpenSSLCertificate> $i_certs */
    public static function byNameEx( array $i_certs, string $i_stName ) : OpenSSLCertificate {
        $crt = self::byName( $i_certs, $i_stName );
        if ( $crt instanceof OpenSSLCertificate ) {
            return $crt;
        }
        $rAllNames = self::getNames( $i_certs );
        throw new RuntimeException(
            "Failed to find certificate for {$i_stName}: " . implode( ', ', $rAllNames )
        );
    }


    public static function exportCSR( string $i_csr ) : string {
        $csr = preg_replace( '/.* REQUEST-+\n(.*)\n-+END.*/s', '$1', $i_csr );
        if ( $csr === null ) {
            throw new RuntimeException( 'Failed to extract CSR' );
        }
        $csr = base64_decode( $csr, true );
        if ( $csr === false ) {
            throw new RuntimeException( 'Failed to decode CSR' );
        }
        return Base64Url::encode( $csr );
    }


    public static function fromBase64Url( string $i_stCert ) : OpenSSLCertificate {
        $stCert = Base64Url::decode( $i_stCert );
        return self::fromBinary( $stCert );
    }


    public static function fromBinary( string $i_stCert ) : OpenSSLCertificate {
        $i_stCert = "-----BEGIN CERTIFICATE-----\n"
            . chunk_split( base64_encode( $i_stCert ), 64 )
            . "-----END CERTIFICATE-----\n";
        $crt = openssl_x509_read( $i_stCert );
        if ( $crt === false ) {
            throw new RuntimeException( 'Failed to decode certificate' );
        }
        return $crt;
    }


    public static function getCN( OpenSSLCertificate $i_cert ) : ?string {
        $rDetails = openssl_x509_parse( $i_cert );
        if ( $rDetails === false ) {
            throw new RuntimeException( 'Unable to parse certificate' );
        }
        if ( isset( $rDetails[ 'subject' ][ 'CN' ] ) ) {
            return $rDetails[ 'subject' ][ 'CN' ];
        }
        if ( isset( $rDetails[ 'extensions' ][ 'subjectAltName' ] ) ) {
            $stSAN = $rDetails[ 'extensions' ][ 'subjectAltName' ];
            $rSAN = explode( ',', $stSAN );
            foreach ( $rSAN as $stSAN ) {
                $stSAN = trim( $stSAN );
                if ( str_starts_with( $stSAN, 'DNS:' ) ) {
                    return substr( $stSAN, 4 );
                }
            }
        }
        return null;
    }


    public static function getExpirationDate( string|OpenSSLCertificate $i_cert ) : int {
        $rDetails = openssl_x509_parse( $i_cert );
        if ( $rDetails === false ) {
            throw new RuntimeException( 'Failed to parse certificate' );
        }
        return $rDetails[ 'validTo_time_t' ];
    }


    /** @param list<string>|string $i_fields */
    public static function getIssuer( string|OpenSSLCertificate $i_cert, string|array $i_fields = 'CN' ) : ?string {
        if ( ! is_array( $i_fields ) ) {
            $i_fields = [ $i_fields ];
        }
        $rDetails = openssl_x509_parse( $i_cert );
        if ( $rDetails === false ) {
            throw new RuntimeException( 'Failed to parse certificate' );
        }
        if ( ! isset( $rDetails[ 'issuer' ] ) ) {
            throw new RuntimeException( 'Failed to find issuer' );
        }
        foreach ( $i_fields as $stField ) {
            if ( isset( $rDetails[ 'issuer' ][ $stField ] ) ) {
                return $rDetails[ 'issuer' ][ $stField ];
            }
        }
        return null;
    }


    /** @param list<string>|string $i_fields */
    public static function getIssuerEx( string|OpenSSLCertificate $i_cert, string|array $i_fields = 'CN' ) : string {
        $nst = self::getIssuer( $i_cert, $i_fields );
        if ( is_string( $nst ) ) {
            return $nst;
        }
        throw new RuntimeException( 'Failed to find issuer' );
    }


    /**
     * @param OpenSSLCertificate[]|string|OpenSSLCertificate $i_cert
     * @return list<string>
     */
    public static function getNames( string|OpenSSLCertificate|array $i_cert ) : array {
        if ( is_array( $i_cert ) ) {
            $rNames = [];
            foreach ( $i_cert as $cert ) {
                $rNames = array_merge( $rNames, self::getNames( $cert ) );
            }
            return $rNames;
        }
        $rDetails = openssl_x509_parse( $i_cert );
        if ( $rDetails === false ) {
            throw new RuntimeException( 'Failed to parse certificate' );
        }
        $rNames = [];
        # Get the main certificate CN (if set).
        if ( isset( $rDetails[ 'subject' ][ 'CN' ] ) ) {
            $rNames[ $rDetails[ 'subject' ][ 'CN' ] ] = 1;
        }

        # Get subject alternative names (SAN).
        if ( isset( $rDetails[ 'extensions' ][ 'subjectAltName' ] ) ) {
            $stSAN = $rDetails[ 'extensions' ][ 'subjectAltName' ];
            $rSAN = explode( ',', $stSAN );
            foreach ( $rSAN as $stSAN ) {
                $stSAN = trim( $stSAN );
                if ( str_starts_with( $stSAN, 'DNS:' ) ) {
                    $rNames[ substr( $stSAN, 4 ) ] = 1;
                }
            }
        }

        return array_map( static function ( $x ) {
            return strval( $x );
        }, array_keys( $rNames ) );

    }


    public static function isExpired( string|OpenSSLCertificate $i_cert ) : bool {
        return self::getExpirationDate( $i_cert ) < time();
    }


    public static function isValid( string|OpenSSLCertificate $i_cert ) : bool {
        if ( $i_cert instanceof OpenSSLCertificate ) {
            return true;
        }
        $cert = openssl_x509_read( $i_cert );
        return false !== $cert;
    }


    public static function keyFromString( OpenSSLAsymmetricKey|string $i_key ) : OpenSSLAsymmetricKey {
        if ( is_string( $i_key ) ) {
            $key = openssl_pkey_get_private( $i_key );
            if ( $key === false ) {
                throw new RuntimeException( 'Failed to read private key' );
            }
            return $key;
        }
        return $i_key;
    }


    public static function keyToString( OpenSSLAsymmetricKey|string $i_key ) : string {
        if ( is_string( $i_key ) ) {
            return trim( $i_key ) . PHP_EOL;
        }
        $stKey = '';
        openssl_pkey_export( $i_key, $stKey );
        return trim( $stKey ) . PHP_EOL;
    }


    /** @param list<string> $i_rNames */
    public static function makeCSR( OpenSSLAsymmetricKey $i_key, array $i_rNames ) : string {
        $tempConf = <<<EOL
[ req ]
distinguished_name = req_distinguished_name
req_extensions = v3_req

[ req_distinguished_name ]

[ v3_req ]
basicConstraints = CA:FALSE
keyUsage = nonRepudiation, digitalSignature, keyEncipherment
subjectAltName = @alt_names

[ alt_names ]

EOL;
        foreach ( $i_rNames as $i => $stName ) {
            $tempConf .= "DNS.$i = $stName\n";
        }
        $tempFile = tempnam( sys_get_temp_dir(), 'csr_' );
        if ( ! is_string( $tempFile ) ) {
            throw new RuntimeException( 'Failed to create temporary file' );
        }
        file_put_contents( $tempFile, $tempConf );
        set_error_handler( null );
        $csr = openssl_csr_new( [
            'ST' => 'United States',
            'C' => 'US',
            'O' => 'Unknown',
        ], $i_key, [
            'digest_alg' => 'sha384',
            'req_extensions' => 'v3_req',
            'config' => $tempFile,
        ] );
        restore_error_handler();
        unlink( $tempFile );
        if ( $csr === false ) {
            $st = self::opensslErrorString();
            throw new RuntimeException( "Failed to create CSR: {$st}" );
        }
        assert( $csr instanceof OpenSSLCertificateSigningRequest );

        $stCSR = '';
        $b = openssl_csr_export( $csr, $stCSR );
        if ( $b === false ) {
            throw new RuntimeException( 'Failed to export CSR' );
        }
        assert( is_string( $stCSR ) );
        return $stCSR;
    }


    public static function makeKey( KeyType $keyType = KeyType::EC ) : OpenSSLAsymmetricKey {
        return match ( $keyType ) {
            KeyType::EC => self::makeKeyEC(),
            KeyType::RSA => self::makeKeyRSA(),
        };
    }


    public static function makeKeyEC() : OpenSSLAsymmetricKey {
        /** @noinspection SpellCheckingInspection */
        $res = openssl_pkey_new( [
            'private_key_type' => OPENSSL_KEYTYPE_EC,
            'curve_name' => 'secp384r1',
            'digest_alg' => 'sha384',
        ] );
        if ( $res === false ) {
            throw new RuntimeException( 'Failed to create key' );
        }
        return $res;
    }


    public static function makeKeyRSA( int $i_uBits = 4096 ) : OpenSSLAsymmetricKey {
        $res = openssl_pkey_new( [
            'private_key_type' => OPENSSL_KEYTYPE_RSA,
            'private_key_bits' => $i_uBits,
            'digest_alg' => 'sha384',
        ] );
        if ( $res === false ) {
            throw new RuntimeException( 'Failed to create key' );
        }
        return $res;
    }


    /**
     * @param list<OpenSSLCertificate|string>|OpenSSLCertificate|string $i_rChain
     */
    public static function makePEM( OpenSSLAsymmetricKey|string     $i_key,
                                    string|OpenSSLCertificate|null  $i_cert = null,
                                    array|string|OpenSSLCertificate $i_rChain = [] ) : string {
        if ( ! is_array( $i_rChain ) ) {
            $i_rChain = [ $i_rChain ];
        }
        if ( $i_cert === null ) {
            if ( empty( $i_rChain ) ) {
                throw new RuntimeException( 'The certificate must be provided or present in the chain.' );
            }
            $i_cert = array_shift( $i_rChain );
        }
        if ( ! self::verifyKey( $i_cert, $i_key ) ) {
            throw new RuntimeException( 'The key does not match the (first) certificate.' );
        }
        $stPEM = self::keyToString( $i_key );
        $stPEM .= self::toString( $i_cert );
        $stPEM .= self::toString( $i_rChain );
        return $stPEM;
    }


    public static function makePEMFromFiles( string  $i_stKeyFile, ?string $i_stCertFile = null,
                                             ?string $i_stChainFile = null ) : string {
        $key = self::readKeyPrivate( $i_stKeyFile );
        $crt = is_string( $i_stCertFile ) ? self::readChain( $i_stCertFile )[ 0 ] : null;
        $rChain = is_string( $i_stChainFile ) ? self::readChain( $i_stChainFile ) : [];
        return self::makePEM( $key, $crt, $rChain );
    }


    /**
     * @param string $i_stText The input string.
     * @param string|null $i_nstCN The CN to match, if desired.
     * @return list<OpenSSLCertificate> All the (matching) certificates in the input string.
     *
     * This is useful for parsing a certificate chain.
     */
    public static function parseChain( string $i_stText, ?string $i_nstCN = null ) : array {
        $x = preg_match_all( '/-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----/s', $i_stText, $rMatches );
        if ( $x === false ) {
            throw new RuntimeException( 'Failed to read certificates' );
        }
        $r = [];
        foreach ( $rMatches[ 0 ] as $stCert ) {
            $crt = openssl_x509_read( $stCert );
            if ( $crt === false ) {
                throw new RuntimeException( 'Failed to decode certificate' );
            }
            $nstName = self::getCN( $crt );
            if ( $i_nstCN !== null && $nstName !== $i_nstCN ) {
                continue;
            }
            $r[] = $crt;
        }
        return $r;
    }


    public static function parsePEM( string $i_stPEM ) : stdClass {
        $x = new stdClass();
        $r = self::parseChain( $i_stPEM );
        $x->key = self::keyFromString( $i_stPEM );
        $x->crt = count( $r ) > 0 ? array_shift( $r ) : null;
        $x->chn = $r;
        return $x;
    }


    /** @param OpenSSLCertificate[] $i_rChain */
    public static function pickCertificateFromChain( array $i_rChain, string $i_stAlias ) : OpenSSLCertificate {
        foreach ( $i_rChain as $crt ) {
            $nstName = self::getCN( $crt );
            if ( $nstName !== $i_stAlias ) {
                continue;
            }
            return $crt;
        }
        throw new RuntimeException( "Failed to find certificate {$i_stAlias}" );
    }


    public static function readCSR( string $i_stFileName ) : string {
        $st = file_get_contents( $i_stFileName );
        if ( ! is_string( $st ) ) {
            throw new RuntimeException( 'Failed to read CSR' );
        }
        return $st;
    }


    /** @return list<OpenSSLCertificate> All the (matching) certificates in the input file. */
    public static function readChain( string $i_stFileName, ?string $i_nstCN = null ) : array {
        $stCert = file_get_contents( $i_stFileName );
        if ( ! is_string( $stCert ) ) {
            throw new RuntimeException( "Failed to read certificate chain {$i_stFileName}" );
        }
        return self::parseChain( $stCert, $i_nstCN );
    }


    public static function readKeyPrivate( string $i_stFileName ) : OpenSSLAsymmetricKey {
        $stKey = file_get_contents( $i_stFileName );
        if ( ! is_string( $stKey ) ) {
            throw new RuntimeException( "Failed to read keyfile {$i_stFileName}" );
        }
        return self::keyFromString( $stKey );
    }


    public static function readPEM( string $i_stFileName ) : stdClass {
        $stPEM = file_get_contents( $i_stFileName );
        if ( ! is_string( $stPEM ) ) {
            throw new RuntimeException( "Failed to read PEM file {$i_stFileName}" );
        }
        return self::parsePEM( $stPEM );
    }


    /**
     * This is mostly useful for generating self-signed certificates
     * for testing purposes.
     */
    public static function signCSR( OpenSSLAsymmetricKey                    $i_key,
                                    OpenSSLCertificateSigningRequest|string $i_csr,
                                    int                                     $i_uDays ) : OpenSSLCertificate {
        $crt = openssl_csr_sign( $i_csr, null, $i_key, $i_uDays, [
            'digest_alg' => 'sha384',
        ] );
        if ( $crt === false ) {
            throw new RuntimeException( 'Failed to sign CSR' );
        }
        return $crt;
    }


    public static function toBase64Url( OpenSSLCertificate $i_cert ) : string {
        return Base64Url::encode( self::toBinary( $i_cert ) );
    }


    public static function toBinary( OpenSSLCertificate $i_cert ) : string {
        $st = self::toString( $i_cert );
        $st = preg_replace( '/.* CERTIFICATE-+\n(.*)\n-+END.*/s', '$1', $st );
        if ( $st === null ) {
            throw new RuntimeException( 'Failed to extract certificate' );
        }
        $st = base64_decode( $st, true );
        if ( $st === false ) {
            throw new RuntimeException( 'Failed to decode certificate' );
        }
        return $st;
    }


    /** @param list<OpenSSLCertificate|string>|OpenSSLCertificate|string $i_cert */
    public static function toString( array|OpenSSLCertificate|string $i_cert ) : string {
        if ( is_string( $i_cert ) ) {
            return trim( $i_cert ) . PHP_EOL;
        }
        $st = '';
        if ( is_array( $i_cert ) ) {
            if ( empty( $i_cert ) ) {
                return '';
            }
            foreach ( $i_cert as $crt ) {
                $st .= trim( self::toString( $crt ) ) . PHP_EOL;
            }
            return trim( $st ) . PHP_EOL;
        }
        openssl_x509_export( $i_cert, $st );
        return trim( $st ) . PHP_EOL;
    }


    public static function verifyKey( OpenSSLCertificate|string $i_cert, OpenSSLAsymmetricKey|string $i_key ) : bool {
        return openssl_x509_check_private_key( $i_cert, $i_key );
    }


    public static function writeCSR( string $i_stFileName, string $i_csr ) : void {
        $stCSR = '';
        openssl_csr_export( $i_csr, $stCSR );
        file_put_contents( $i_stFileName, $stCSR );
    }


    /** @param list<OpenSSLCertificate>|OpenSSLCertificate|string $i_cert */
    public static function writeChain( string $i_stFileName, array|string|OpenSSLCertificate $i_cert ) : void {
        $i_cert = self::toString( $i_cert );
        file_put_contents( $i_stFileName, $i_cert );
    }


    public static function writeKeyPrivate( string $i_stFileName, OpenSSLAsymmetricKey $i_key ) : void {
        $stKey = '';
        openssl_pkey_export( $i_key, $stKey );
        $b = file_put_contents( $i_stFileName, $stKey );
        if ( false === $b ) {
            throw new RuntimeException( "Unable to write keyfile {$i_stFileName}" );
        }
    }


    private static function opensslErrorString() : string {
        $r = self::opensslErrors();
        if ( ! is_array( $r ) ) {
            return '(no openssl error)';
        }
        return implode( ', ', $r );
    }


    /** @return string[]|null */
    private static function opensslErrors() : ?array {
        $out = [];
        while ( false !== ( $x = openssl_error_string() ) ) {
            $out[] = $x;
        }
        if ( empty( $out ) ) {
            return null;
        }
        return $out;
    }


}
