/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package pv181.jca;

import java.io.IOException;
import java.io.InputStream;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import javax.xml.bind.DatatypeConverter;

/**
 *
 * @author dusanklinec
 */
public class Demo {
    public static void main(String args[]) throws Exception {
        keySerializationDemo();
        certificateLoadDemo();
    } 
    
    /**
     * Demo showing key serialization.
     * 
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeySpecException 
     */
    public static void keySerializationDemo() throws NoSuchAlgorithmException, InvalidKeySpecException {
        // Generate a key-pair, public & private key for RSATest algorithm.
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        KeyPair kp = kpg.generateKeyPair();
        
        byte[] serializedPrivate = Globals.serializeKey(kp.getPrivate());
        byte[] serializedPublic = Globals.serializeKey(kp.getPublic());
        
        System.out.println("Encoded private key, base64: \n" + DatatypeConverter.printBase64Binary(serializedPrivate));
        
        PublicKey pubKey = Globals.deserializePublicKey(serializedPublic);
        PrivateKey privKey = Globals.deserializePrivateKey(serializedPrivate);
        
        System.out.println(String.format("PubKey: [%s], privKey[%s]", pubKey, privKey));
        System.out.println("Reconstructed private key, encoded, base64: \n" 
                + DatatypeConverter.printBase64Binary(privKey.getEncoded()));
    }
   
    /**
     * Loads certificate and a private key from resources.
     * @throws CertificateException
     * @throws IOException 
     */
    public static void certificateLoadDemo() throws CertificateException, IOException{
         // Read CA certificate from PEM file by using PEMParser from BouncyCastle library.
        InputStream resCrt = Demo.class.getResourceAsStream("res/ca.crt");
        X509Certificate crt = Globals.getX509Certificate(Globals.readCertFromPEM(resCrt));
        
        // Read CA private key.
        InputStream resKey = Demo.class.getResourceAsStream("res/ca.key");
        PrivateKey privKey = Globals.readKeyFromPEM(resKey, null).getPrivate();
        
        System.out.println(String.format("\nPrivateKey: %s; \n\nCertificate: %s", privKey, crt));
    }
}
