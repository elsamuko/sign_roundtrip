
// g++ -std=c++11  digest2DER.cpp -o digest2DER -lcrypto

#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>
#include <openssl/pem.h>

std::string fromFile( const std::string& filename ) {
    std::ifstream file( filename.c_str() );
    return std::string( ( std::istreambuf_iterator<char>( file ) ), ( std::istreambuf_iterator<char>() ) );
}

std::string toString( std::vector<unsigned char>& data ) {
    std::stringstream ss;

    for( unsigned char c : data ) {
        ss << c;
    }

    return ss.str();
}

std::string digest2DER( const std::string& digest ) {

    X509_ALGOR algor;
    ASN1_TYPE parameter;
    ASN1_OCTET_STRING sdigest;

    X509_SIG sig;
    sig.algor = &algor;
    sig.algor->algorithm = OBJ_nid2obj( NID_sha1 );

    parameter.type = V_ASN1_NULL;
    parameter.value.ptr = NULL;
    sig.algor->parameter = &parameter;

    sig.digest = &sdigest;
    sig.digest->length = digest.size();
    sig.digest->data   = ( unsigned char* ) digest.c_str();

    // get size from DER
    size_t i = i2d_X509_SIG( &sig, NULL );

    // write DER to array
    std::vector<unsigned char> DER( i );
    unsigned char* pDER = DER.data();
    i2d_X509_SIG( &sig, &pDER );

    return toString( DER );
}

int usage() {
    std::cout << "Usage: " << std::endl;
    std::cout << "    digest2DER <filename> " << std::endl;
    return 0;
}

int main( int argc, char** argv ) {

    if( argc != 2 ) {
        return usage();
    }

    // read digest
    std::string digest = fromFile( argv[1] );
    std::cout << digest2DER( digest );

    return 0;
}
