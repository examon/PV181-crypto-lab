/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package pv181.jca;

import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.io.Reader;
import java.io.Writer;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.openssl.PEMDecryptorProvider;
import org.bouncycastle.openssl.PEMEncryptedKeyPair;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.PEMWriter;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.openssl.jcajce.JcePEMDecryptorProviderBuilder;
import org.bouncycastle.util.io.pem.PemObject;

/**
 *
 * @author dusanklinec
 */
public class Globals {
    public static final Provider PROVIDER = new org.bouncycastle.jce.provider.BouncyCastleProvider();
    
    // Adds BouncyCastle provider.
    static {
        Security.addProvider(PROVIDER);
    }

    /**
     * Prints array of bytes in hexadecimal notation, aligned on 16 bytes.
     * Same as @see{Globals.bytesToHexString}
     * 
     * @param b
     * @return
     */
    public static String bytesToHex(byte[] b) {
        return bytesToHex(b, true, false);
    }
    
    /**
     * Prints array of bytes in hexadecimal notation, aligned on 16 bytes.
     * 
     * @param b
     * @param prettyFormat if true output is formatted more human friendly 
     * @return
     */
    public static String bytesToHex(byte[] b, boolean prettyFormat) {
        return bytesToHex(b, prettyFormat, true);
    }
    
    /**
     * Prints array of bytes in hexadecimal notation, aligned on 16 bytes.
     * @param b
     * @param prettyFormat
     * @param hexForm
     * @return 
     */
    public static String bytesToHex(byte[] b, boolean prettyFormat, boolean hexForm) {
        final StringBuilder sb = new StringBuilder();
        for (int i = 0; i < b.length; i++) {
            if (prettyFormat){
                sb.append(String.format(hexForm ? "0x%02X" : "%02X", b[i]));
                sb.append((i % 16) == 15 ? "\n" : (i + 1 == b.length ? " " : " "));
            } else {
                sb.append(String.format("%02X", b[i]));
            }
        }
        return sb.toString();
    }
    
    /**
     * Prints array of bytes in hexadecimal notation, aligned on 16 bytes.
     * @param b
     * @return
     */
    public static String print(byte[] b) {
        return bytesToHex(b, true, false);
    }
    
    /**
     * Prints array of bytes in hexadecimal notation, aligned on 16 bytes.
     * @param b
     * @return
     */
    public static String bytesToHexString(byte[] b) {
        return bytesToHex(b, true, false);
    }
    
    /**
     * Bytes to hex - lowercase, no spaces.
     * Useful for comparing message digests.
     * 
     * @param b byte array to transform to hex string
     * @return
     */
    public static String bytesToLowHex(byte[] b) {
        final StringBuilder sb = new StringBuilder();
        for (int i = 0; i < b.length; i++) {
            sb.append(String.format("%02x", b[i]));
        }
        return sb.toString();
    }
    
    /**
     * Serializes Key to byte array.
     * 
     * @param key
     * @return 
     */
    public static byte[] serializeKey(Key key){
        return key.getEncoded();
    }
    
    /**
     * Deserializes private key stored as a byte array. 
     * @param key
     * @return
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeySpecException 
     */
    public static PrivateKey deserializePrivateKey(byte[] key) throws NoSuchAlgorithmException, InvalidKeySpecException{
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(key);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return keyFactory.generatePrivate(keySpec);
    }
    
    /**
     * Deserializes public key stored as a byte array. 
     * @param key
     * @return
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeySpecException 
     */
    public static PublicKey deserializePublicKey(byte[] key) throws NoSuchAlgorithmException, InvalidKeySpecException{
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(key);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return keyFactory.generatePublic(keySpec);
    }
    
    /**
     * Generates AES encryption key based on given string pass-phrase and random
     * (public) salt.
     * 
     * Uses PBKDF2 as key derivating function.
     * https://en.wikipedia.org/wiki/PBKDF2
     * 
     * @param passphrase
     * @param salt
     * @param keySize
     * @return
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeySpecException 
     */
    public SecretKey pbkdf2(String passphrase, byte[] salt, int keySize) throws NoSuchAlgorithmException, InvalidKeySpecException{
        // derive AESTest encryption key using password and salt
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
        KeySpec spec = new PBEKeySpec(passphrase.toCharArray(), salt, 1024, keySize);
        SecretKey tmp = factory.generateSecret(spec);
        SecretKey secret = new SecretKeySpec(tmp.getEncoded(), "AES");
        
        return secret;
    }
    
    /**
     * Reads PEM file and extracts X509Certificate from it.
     * @param crt
     * @return
     * @throws IOException 
     */
    public static X509CertificateHolder readCertFromPEM(InputStream crt) throws IOException{
        Object obj = readPEM(crt);
        if (obj instanceof X509CertificateHolder){
            return (X509CertificateHolder) obj;
        } else {
            throw new IllegalArgumentException("Given PEM file does not contain certificate");
        }
    }
    
    /**
     * Converts X509CertificateHolder from BouncyCastle library to X509Certificate.
     * @param h
     * @return 
     * @throws java.security.cert.CertificateException 
     */
    public static X509Certificate getX509Certificate(X509CertificateHolder h) throws CertificateException{
        return new JcaX509CertificateConverter().setProvider(PROVIDER).getCertificate(h);
    }
    
    /**
     * Reads key from PEM file. Able to read both encrypted and plain keys.
     * @param s
     * @param password
     * @return
     * @throws IOException 
     */
    public static KeyPair readKeyFromPEM(InputStream s, String password) throws IOException{
        // This is PEM decryptor in a case where key is stored in ecnrypted form
        PEMDecryptorProvider decProv = new JcePEMDecryptorProviderBuilder().build(password==null ? null : password.toCharArray());
        
        // PEM key converter converts PEMKeyPair type to KeyPair
        JcaPEMKeyConverter converter = new JcaPEMKeyConverter().setProvider(PROVIDER);
        
        // Read the object itself from the PEM file
        Object obj = readPEM(s);
        if (obj instanceof PEMEncryptedKeyPair) {
            return converter.getKeyPair(((PEMEncryptedKeyPair) obj).decryptKeyPair(decProv));
        } else {
            return converter.getKeyPair((PEMKeyPair) obj);
        }
    }
    
    /**
     * Basic PEM file parser, returns parsed object.
     * @param s
     * @return
     * @throws IOException 
     */
    public static Object readPEM(InputStream s) throws IOException{
        // initialize buffered reader of input stream
        Reader fRd = new BufferedReader(new InputStreamReader(s));
        
        // PEM parser from Bouncy castle library
        PEMParser parser = new PEMParser(fRd);
        
        // Parse given PEM file, decide if it is X509Certificate
        return parser.readObject();
    }
    
    /**
     * Returns PEM format of Certificate
     *
     * @param cert
     * @return
     * @throws IOException
     * @throws CertificateEncodingException
     */
    public byte[] getCertificateAsPEM(X509Certificate cert) throws IOException, CertificateEncodingException {
        final String type = "CERTIFICATE";
        byte[] encoding = cert.getEncoded();
        PemObject pemObject = new PemObject(type, encoding);
        return createPEM(pemObject);
    }
    
    /**
     * Creates PEM object representation and returns byte array
     *
     * @param obj
     * @return
     * @throws IOException
     */
    public byte[] createPEM(Object obj) throws IOException {
        ByteArrayOutputStream barrout = new ByteArrayOutputStream();
        this.createPEM(new OutputStreamWriter(barrout), obj);
        // return encoded PEM data - collect bytes from ByteArrayOutputStream		
        return barrout.toByteArray();
    }

    /**
     * Creates PEM file from passed object
     *
     * @param writer
     * @param obj
     * @throws IOException
     */
    public void createPEM(Writer writer, Object obj) throws IOException {
        PEMWriter pemWrt = new PEMWriter(writer);
        pemWrt.writeObject(obj);
        pemWrt.flush();
        pemWrt.close();
    }
}
