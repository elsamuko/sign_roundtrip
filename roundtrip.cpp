
// g++ -std=c++11 roundtrip.cpp -o roundtrip -lcrypto

#include <iostream>
#include <fstream>
#include <memory>
#include <string>
#include <vector>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <cstring>

namespace encoding {

    enum Type {
        Binary,
        Base64
    };

    std::string encodeBase64( const std::string& input ) {
        if( input.empty() ) {
            return input;
        }

        std::string ret;

        BIO* b64 = BIO_new( BIO_f_base64() );
        BIO_set_flags( b64, BIO_FLAGS_BASE64_NO_NL );

        BIO* bmem = BIO_new( BIO_s_mem() );

        b64 = BIO_push( b64, bmem );

        BIO_write( b64, input.data(), ( int ) input.length() );
        BIO_flush( b64 );

        BUF_MEM* bptr;
        BIO_get_mem_ptr( b64, &bptr );

        ret.resize( bptr->length );
        memcpy( &ret[0], bptr->data, bptr->length );

        BIO_free_all( b64 );

        return ret;
    }

    std::string decodeBase64( const std::string& input ) {
        if( input.empty() ) {
            return input;
        }

        std::vector<char> outbuf( input.length() );

        BIO* mbio   = BIO_new( BIO_s_mem() );
        BIO* b64bio = BIO_new( BIO_f_base64() );

        BIO_set_flags( b64bio, BIO_FLAGS_BASE64_NO_NL );
        BIO_write( mbio, input.c_str(), ( int ) input.length() );

        BIO* bio = BIO_push( b64bio, mbio );
        int  len = BIO_read( b64bio, &outbuf[0], ( int ) input.length() );

        BIO_free_all( bio );

        std::string ret( &outbuf[0], len );

        return ret;
    }
} // namespace encoding

namespace crypto {

    std::vector<unsigned char> digestSHA1( const std::string& data ) {

        std::vector<unsigned char> digest( SHA_DIGEST_LENGTH );

        int status = EXIT_FAILURE;

        do { /* once */
            SHA_CTX sha_ctx = { 0 };

            if( 1 != SHA1_Init( &sha_ctx ) ) {
                break;
            }

            if( 1 != SHA1_Update( &sha_ctx, data.c_str(), data.size() ) ) {
                break;
            }

            if( 1 != SHA1_Final( digest.data(), &sha_ctx ) ) {
                break;
            }

            status = EXIT_SUCCESS;

        } while( false );

        if( status == EXIT_FAILURE ) {
            std::string error = std::string( ERR_error_string( ERR_get_error(), NULL ) );
            std::cout << "ERROR     : " << error << std::endl;
        }

        return digest;
    }

    bool verifyData( const std::string& signature, const std::string& data, RSA* key, encoding::Type coding = encoding::Base64 ) {

        // if the signature is base64, decode it first
        if( coding == encoding::Base64 ) {
            std::string decoded = encoding::decodeBase64( signature );
            return verifyData( decoded, data, key, encoding::Binary );
        }

        int status = EXIT_FAILURE;

        std::vector<unsigned char> digest = crypto::digestSHA1( data );

        do { /* once */

            if( 1 != RSA_verify( NID_sha1, digest.data(), digest.size(), ( unsigned char* ) signature.c_str(), signature.size(), key ) ) {
                break ;
            }

            status = EXIT_SUCCESS;

        } while( false );

        if( status == EXIT_FAILURE ) {
            std::string error = std::string( ERR_error_string( ERR_get_error(), NULL ) );
            std::cout << "ERROR     : " << error << std::endl;
        }

        return status == EXIT_SUCCESS;
    }

    bool signData( std::string& signature, const std::string& data, RSA* key, encoding::Type coding = encoding::Base64 ) {

        if( !key ) {
            return false;
        }

        int status = EXIT_FAILURE;

        std::vector<unsigned char> digest = crypto::digestSHA1( data );
        std::cout << "SHA1      : " << encoding::encodeBase64( std::string( ( char* ) digest.data(), digest.size() ) ) << std::endl;

        do { /* once */

            unsigned int size = RSA_size( key );
            signature.resize( size, '\0' );

            if( 1 != RSA_sign( NID_sha1, digest.data(), digest.size(), ( unsigned char* ) signature.c_str(), &size, key ) ) {
                break ;
            }

            status = EXIT_SUCCESS;

        } while( false );

        if( status == EXIT_FAILURE ) {
            std::string error = std::string( ERR_error_string( ERR_get_error(), NULL ) );
            std::cout << "ERROR     : " << error << std::endl;
        }

        // if base64 is requested, encode the signature
        if( coding == encoding::Base64 ) {
            signature = encoding::encodeBase64( signature );
        }

        return ( status == EXIT_SUCCESS );
    }
} // namespace crypto

namespace rsa {
    std::shared_ptr<RSA> fromString( const std::string& data, bool privkey ) {

        std::shared_ptr<RSA> key;
        std::shared_ptr< BIO > bio( BIO_new_mem_buf( ( void* ) data.c_str(), data.size() ), BIO_free );

        if( !privkey ) {
            key = std::shared_ptr<RSA>( PEM_read_bio_RSA_PUBKEY( bio.get(), NULL, NULL, NULL ), RSA_free );
        } else {
            key = std::shared_ptr<RSA>( PEM_read_bio_RSAPrivateKey( bio.get(), NULL, NULL, NULL ), RSA_free );
        }

        return key;
    }
} // namespace rsa

std::string fromFile( const std::string& filename ) {
    std::ifstream pubFile( filename.c_str() );
    return std::string( ( std::istreambuf_iterator<char>( pubFile ) ), ( std::istreambuf_iterator<char>() ) );
}

int main( int argc, char** argv ) {

    // some data
    std::string data     = fromFile( "data.txt" );
    
    // load keys
    std::string sKeyPub  = fromFile( "public.pem" );
    std::string sKeyPriv = fromFile( "private.pem" );

    std::shared_ptr<RSA> keyPriv = rsa::fromString( sKeyPriv, true );
    std::shared_ptr<RSA> keyPub = rsa::fromString( sKeyPub, false );

    // sign and verify
    bool success = true;
    std::string signature;

    success &= crypto::signData( signature, data, keyPriv.get() );
    success &= crypto::verifyData( signature, data, keyPub.get() );

    // info
    std::cout << "OK        : " << ( success ? "true" : "false" ) <<  std::endl;
    std::cout << "Signature : " << signature <<  std::endl;

    return 0;
}


