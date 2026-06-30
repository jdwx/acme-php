<?php


declare( strict_types = 1 );


namespace JDWX\ACME;


use RuntimeException;


final class IOHelper {


    /** @noinspection PhpUsageOfSilenceOperatorInspection */
    public static function readFile( string $i_stFileName ) : string {
        $f = @fopen( $i_stFileName, 'rb' );
        if ( $f === false ) {
            throw new RuntimeException( "Failed to open keyfile {$i_stFileName}" );
        }
        if ( ! flock( $f, LOCK_SH ) ) {
            fclose( $f );
            throw new RuntimeException( "Failed to acquire shared lock on keyfile {$i_stFileName}" );
        }
        $st = stream_get_contents( $f );
        if ( ! fclose( $f ) ) {
            throw new RuntimeException( "Failed to close keyfile {$i_stFileName}" );
        }
        return $st;
    }


    /** @noinspection PhpUsageOfSilenceOperatorInspection */
    public static function writeFile( string $i_stFileName, string $i_stData, int $i_uMask,
                                      bool   $i_bAllowOverwrite = false ) : void {
        if ( file_exists( $i_stFileName ) || is_link( $i_stFileName ) ) {
            if ( ! $i_bAllowOverwrite ) {
                throw new RuntimeException( "Refusing to overwrite existing file {$i_stFileName}" );
            }
            @unlink( $i_stFileName );
        }

        $uOldUmask = umask( 0777 - $i_uMask );
        try {
            $f = @fopen( $i_stFileName, 'xb' );
            if ( $f === false ) {
                throw new RuntimeException( "Failed to open file for write {$i_stFileName}" );
            }
            chmod( $i_stFileName, $i_uMask ); # Belt and suspenders.
            if ( ! @flock( $f, LOCK_EX ) ) {
                fclose( $f );
                @unlink( $i_stFileName );
                throw new RuntimeException( "Failed to acquire exclusive lock on file {$i_stFileName}" );
            }
        } finally {
            umask( $uOldUmask );
        }

        /** @phpstan-ignore-next-line */
        assert( isset( $f ) );
        if ( false === @fwrite( $f, $i_stData ) ) {
            fclose( $f );
            @unlink( $i_stFileName );
            throw new RuntimeException( "Failed to write file {$i_stFileName}" );
        }
        if ( ! fclose( $f ) ) {
            @unlink( $i_stFileName );
            throw new RuntimeException( "Failed to close file after write {$i_stFileName}" );
        }
    }


}
