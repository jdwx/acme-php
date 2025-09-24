<?php


declare( strict_types = 1 );


namespace JDWX\ACME;


use Exception;
use JDWX\ACME\Exceptions\RuntimeException;
use JDWX\Args\MissingArgumentException;
use JDWX\Config\ConfigDB;
use JDWX\Json\Json;
use JDWX\Param\IParameter;
use JDWX\Strict\OK;


class Interpreter extends \JDWX\CLI\Interpreter {


    private ConfigDB $cfg;

    private Client $client;

    private string $stOrderStatePath;

    private string $stSection;


    /** @param list<string> $argv */
    public function __construct( array $argv ) {
        parent::__construct( 'acme> ', $argv );
        $stSection = $this->args()->shiftString();
        if ( ! is_string( $stSection ) ) {
            throw new MissingArgumentException( "Requires \"production\" or \"staging\"" );
        }
        $this->stSection = $stSection;
        $this->cfg = ConfigDB::fromFile( 'acme.ini' );
        $stPrivateKeyPath = $this->cfgGet( 'private-key-path' )->asString();
        $this->stOrderStatePath = $this->cfgGet( 'order-state-path' )->asString();

        $stWorkDir = dirname( $stPrivateKeyPath );
        if ( ! is_dir( $stWorkDir ) ) {
            echo "Creating work directory: {$stWorkDir}\n";
            OK::mkdir( $stWorkDir, 0700, true );
        }

        $stCertDirectory = $this->cfgGet( 'certs-dir' )->asString();
        if ( ! is_dir( $stCertDirectory ) ) {
            echo "Creating certificate directory: {$stCertDirectory}\n";
            OK::mkdir( $stCertDirectory, 0700, true );
        }
        $jwk = JWT::getOrCreateKey( $stPrivateKeyPath );
        $acme = new ACMEv2( $this->cfgGet( 'directory-url' )->asString() );
        $this->client = new Client( $jwk, $acme );
        $this->addCommandClass( Commands\CommandAccount::class );
        $this->addCommandClass( Commands\CommandAuthorizations::class );
        $this->addCommandClass( Commands\CommandCertificate::class );
        $this->addCommandClass( Commands\CommandChallenges::class );
        $this->addCommandClass( Commands\CommandCheckChallenge::class );
        $this->addCommandClass( Commands\CommandDirectory::class );
        $this->addCommandClass( Commands\CommandFinalize::class );
        $this->addCommandClass( Commands\CommandKeyAuthorization::class );
        $this->addCommandClass( Commands\CommandNewAccount::class );
        $this->addCommandClass( Commands\CommandNewOrder::class );
        $this->addCommandClass( Commands\CommandOrder::class );
        $this->addCommandClass( Commands\CommandRevoke::class );
        $this->addCommandClass( Commands\CommandUpdate::class );
        $this->addCommandClass( Commands\CommandValidate::class );
    }


    /** @param string ...$i_args */
    public function cfgGet( ...$i_args ) : IParameter {
        return $this->cfg->get( $this->stSection, ... $i_args );
    }


    /** @param string ...$i_args */
    public function cfgHas( ...$i_args ) : bool {
        return $this->cfg->hasKey( $this->stSection, ... $i_args );
    }


    public function client() : Client {
        return $this->client;
    }


    public function loadOrder( string $i_stName ) : ?Order {
        $stURL = $this->loadOrderURL( $i_stName );
        if ( ! is_string( $stURL ) ) {
            return null;
        }
        return $this->client->order( $stURL, $i_stName );
    }


    public function loadOrderEx( string $i_stName ) : Order {
        $order = $this->loadOrder( $i_stName );
        if ( $order instanceof Order ) {
            return $order;
        }
        throw new RuntimeException( "Order not found: {$i_stName}" );
    }


    public function loadOrderURL( string $i_stName ) : ?string {
        $r = $this->loadOrders();
        return $r[ $i_stName ] ?? null;
    }


    public function loadOrderURLEx( string $i_stName ) : string {
        $nst = $this->loadOrderURL( $i_stName );
        if ( is_string( $nst ) ) {
            return $nst;
        }
        throw new RuntimeException( "Order not found: {$i_stName}" );
    }


    /** @return array<string, string> */
    public function loadOrders() : array {
        if ( ! file_exists( $this->stOrderStatePath ) ) {
            return [];
        }
        $bst = file_get_contents( $this->stOrderStatePath );
        if ( ! is_string( $bst ) || '' === $bst ) {
            throw new RuntimeException( "Failed to read order state file {$this->stOrderStatePath}" );
        }
        return Json::decodeStringMap( $bst );
    }


    /** @param list<string> $i_rNames */
    public function saveOrder( array $i_rNames, string $i_stURL ) : void {
        $r = $this->loadOrders();
        var_dump( $r );
        foreach ( $i_rNames as $stName ) {
            $r[ $stName ] = $i_stURL;
        }
        file_put_contents( $this->stOrderStatePath, Json::encode( $r ) );
    }


    protected function handleException( Exception $i_ex ) : ?int {
        var_dump( $i_ex );
        return 10;
    }


    /** @param list<string>|null $i_argv */
    protected function newArguments( ?array $i_argv ) : Arguments {
        global $argv;
        return new Arguments( $this, $i_argv ?? $argv );
    }


}
