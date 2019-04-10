#!/usr/bin/env groovy

@Grab(group='org.bouncycastle', module='bcprov-jdk15on', version='1.61')
@Grab(group='org.bouncycastle', module='bcpkix-jdk15on', version='1.61')

import java.security.*
import java.security.spec.*
import org.bouncycastle.asn1.x509.*
import org.bouncycastle.asn1.pkcs.*
import org.bouncycastle.crypto.params.*
import org.bouncycastle.crypto.util.*
import org.bouncycastle.openssl.*

byte[] sha256( byte[] data ) {
    MessageDigest md = MessageDigest.getInstance( "SHA-256" )
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
    
    return rsaPub
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
    
    return rsaPriv
}


// some test data
String data = new File( 'data.txt' ).getText()

// the keys
String publicPEM  = new File( 'public.pem' ).getText()
String privatePEM = new File( 'private.pem' ).getText()

PublicKey pubKey  = getPublicKeyFromString( publicPEM )
PrivateKey privKey = getPrivateKeyFromString( privatePEM )


// sign and verify
Signature signer = Signature.getInstance( "SHA256withRSA" )
signer.initSign( privKey )
signer.update( data.getBytes() )
byte[] signature = signer.sign()

Signature verifier = Signature.getInstance( "SHA256withRSA" );
verifier.initVerify( pubKey );
verifier.update( data.getBytes() )
boolean ok = verifier.verify( signature );


// info
println "SHA256    : ${sha256( data.getBytes() ).encodeBase64()}"
println "OK        : ${ok}"
println "Signature : ${signature.encodeBase64()}"


