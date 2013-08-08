
import java.security.*
import java.security.spec.*
import org.bouncycastle.asn1.x509.*
import org.bouncycastle.asn1.pkcs.*
import org.bouncycastle.crypto.params.*
import org.bouncycastle.crypto.util.*
import org.bouncycastle.openssl.*

byte[] sha1( byte[] data ) {
    MessageDigest md = MessageDigest.getInstance( "SHA-1" )
    md.update( data )
    md.digest()
}

PublicKey getPublicKeyFromString( String keystr ) throws Exception {

    PublicKey rsaPub = null
    SubjectPublicKeyInfo info = null;

    PEMParser parser = new PEMParser( new StringReader( keystr ) );
    Object object = parser.readObject()
    // println "parsed object is ${object.getClass()}"
    
    if ( object instanceof SubjectPublicKeyInfo ) {
        info = ( SubjectPublicKeyInfo ) object
    
        RSAKeyParameters rsa = ( RSAKeyParameters ) PublicKeyFactory.createKey( info )
        RSAPublicKeySpec rsaSpec = new RSAPublicKeySpec( rsa.getModulus(), rsa.getExponent() )
        KeyFactory kf = KeyFactory.getInstance( "RSA" )
        rsaPub = kf.generatePublic( rsaSpec )
    }
    
    rsaPub
}

PrivateKey getPrivateKeyFromString( String keystr ) throws Exception {

    PrivateKey rsaPriv = null
    PrivateKeyInfo  info = null
    
    PEMParser parser = new PEMParser( new StringReader( keystr ) )
    Object object = parser.readObject()
    // println "parsed object is ${object.getClass()}"
    
    if ( object instanceof PEMKeyPair  ) {
        PEMKeyPair pair = ( PEMKeyPair ) object
        info = pair.getPrivateKeyInfo()
    } else if ( object instanceof PrivateKeyInfo  ) { 
        info = ( PrivateKeyInfo  ) object
    }
    
    if( info ) {
        RSAKeyParameters rsa = ( RSAKeyParameters ) PrivateKeyFactory.createKey( info )
        RSAPrivateKeySpec rsaSpec = new RSAPrivateKeySpec( rsa.getModulus(), rsa.getExponent() )
        KeyFactory kf = KeyFactory.getInstance( "RSA" )
        rsaPriv = kf.generatePrivate( rsaSpec )
    }
    
    rsaPriv
}


// some test data
String data = new File( 'data.txt' ).getText()

// the keys
String publicPEM  = new File( 'public.pem' ).getText()
String privatePEM = new File( 'private.pem' ).getText()

PublicKey pubKey  = getPublicKeyFromString( publicPEM )
PrivateKey privKey = getPrivateKeyFromString( privatePEM )


// sign and verify
Signature instance = Signature.getInstance( "SHA1withRSA" )
instance.initSign( privKey )
instance.update( data.getBytes() )
byte[] signature = instance.sign()

Signature instance2 = Signature.getInstance( "SHA1withRSA" );
instance2.initVerify( pubKey );
instance2.update( data.getBytes() )
boolean ok = instance2.verify( signature );


// info
println "SHA1      : ${sha1( data.getBytes() ).encodeBase64()}"
println "OK        : ${ok}"
println "Signature : ${signature.encodeBase64()}"


