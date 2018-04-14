/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package pv181.jca.homework;

import com.google.protobuf.ByteString;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.xml.bind.DatatypeConverter;
import pv181.jca.Globals;
import pv181.jca.protobuf.entities.Messages;

/**
 * Assignment to be specified.
 * Please use this source file to implement main functionality.
 *
 * TODO: install unlimited jurisdiction files - you will need that.
 *
 * @author dusanklinec
 */
public class HashCollisions {
    public static void main(String args[]) throws NoSuchAlgorithmException, NoSuchPaddingException {
        // You are supposed to solve the assignment here...
        
        // TODO: Compute your digest here.
        byte[] digest = new byte[32];
        
        // I have a demo digest here to demonstrate a valid example.
        // Before starting working on the assignment, delete the following line!
        digest = DatatypeConverter.parseBase64Binary("mHZUC0lieA8njlC1XNWca1KOrvax+wm2djQutxEZgak=");
        
        // Part 1 - build a new protobuf message.
        Messages.HashMessage.Builder builder = Messages.HashMessage.newBuilder();
        
        // Put values to the builder.
        builder.setUco("987654"); // TODO: change to your UCO.
        builder.setHashType(1); // Constant, leave 1.
        builder.setHashInput("987654:476346608"); // TODO: add given input hash you found.
        builder.setHash(ByteString.copyFrom(digest)); // Result digest.
        
        // TODO: compute HMAC, AES, RSA, Signature on "digest".
        
        // AES - encrypt digest.
        Cipher aes = Cipher.getInstance("AES/CBC/PKCS5Padding");
        byte[] iv = null;
        byte[] key = null;
        // generate random AES IV, store it to the message.
        //    builder.setAesIv(ByteString.copyFrom(iv));
        // generate random AES key, store it to the message.
        //    builder.setAesKey(ByteString.copyFrom(key))
        // aes.init(...) - initialize
        // byte[] aesCipher = aes.doFinal(...); 
        //builder.setAesCiphertext(ByteString.copyFrom(aesCipher));
        
        // RSA - encrypt digest.
        Cipher rsa = Cipher.getInstance("RSA/ECB/PKCS1PADDING");
        // Generate public,private key pair.
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(8192); // this will take some time, be patient
        KeyPair kp = kpg.generateKeyPair();
        PrivateKey aPrivate = kp.getPrivate();
        PublicKey aPublic = kp.getPublic();
        // Set generated key pair to the message so we can verify your result.
        builder.setPrivateKey(ByteString.copyFrom(Globals.serializeKey(aPrivate)));
        builder.setPublicKey(ByteString.copyFrom(Globals.serializeKey(aPublic)));
        
        // rsa.init(...) - initialize rsa cipher in encryption mode with a suitable key.
        // byte[] rsaCipher = rsa.doFinal(...); 
        //builder.setRsaCiphertext(ByteString.copyFrom(rsaCipher));
        
        // RSA Signature - sign digest.
        java.security.Signature sig = java.security.Signature.getInstance("SHA1WithRSA");
        // Compute signature with sig object on digest. Read documentation to figure out how.
        // byte[] rsaSign = sig.sign();
        //builder.setRsaSignature(ByteString.copyFrom(Globals.serializeKey(rsaSign)));
        
        // HMAC - hmac digest.
        Mac mac = Mac.getInstance("HmacSHA1");
        // Generate a random hmac key. store it to the message.
        //   builder.setHmacKey(ByteString.copyFrom(hmacKey));
        // Generate hmac on digest and store it to the message.
        //   builder.setHmac(ByteString.copyFrom(hmac));
        
        // Build the final message.
        Messages.HashMessage msg = builder.build();
        
        // Print encoded message
        System.out.println("Demo message: " + msg.toString());
        byte[] msgCoded = msg.toByteArray();
        final String msgBase64encoded = DatatypeConverter.printBase64Binary(msgCoded);
        // TODO: save msgBase64encoded to the uco_hash.txt, ZIP it together with the source file
        // and submit to IS.
        
        // Yuo can verify your result by calling the following function:
        verify(msgBase64encoded);
    } 
    
    
    /**
     * Function provided to verify your result.
     * Warning! This method does not verify correctness of the HMAC, AES, RSA & Signature values.
     * 
     * @param encoded 
     */
    public static void verify(String encoded) throws NoSuchAlgorithmException{
        Messages.HashMessage msg = null;
        System.out.println("=================================================");
        System.out.println("Result verification started\n");
        try {
            msg = Messages.HashMessage.parseFrom(DatatypeConverter.parseBase64Binary(encoded));
            System.out.println("Reconstructed message: " + msg);
            
            if (msg == null){
                throw new IllegalArgumentException("Reconstructed message is null!");
            }
            
            if (msg.getHash() == null || msg.getUco() == null || msg.getHashInput() == null){
                throw new IllegalArgumentException("Some of the message field is null!");
            }
        } catch(Exception ex){
            System.out.println("Exception! Message is not properly formatted.");
            ex.printStackTrace();
            return;
        }
        
        final String uco = msg.getUco();
        
        // Check format
        if (uco.length()<6){
            throw new IllegalArgumentException("Your UCO has invalid format: " + uco);
        }
        
        if (msg.getHashInput().startsWith(uco)==false){
            throw new IllegalArgumentException("Your hash input string is not of a valid format " + msg.getHashInput());
        }
        
        byte[] hash = MessageDigest.getInstance("SHA-256").digest(msg.getHashInput().getBytes());
        
        if (       uco.substring(0, 2).equalsIgnoreCase(String.format("%02x", hash[0]))
                && uco.substring(2, 4).equalsIgnoreCase(String.format("%02x", hash[1]))
                && uco.substring(4, 6).equalsIgnoreCase(String.format("%02x", hash[2]))
                && (hash[3] & ((byte)0xF0)) == 0)
        {
            System.out.println(String.format("Your solutions seems correct (if your UCO is %s)! Congrats. Hash:\n%s", uco, Globals.bytesToHex(hash)));
            int awesomenessLevel = 0;
            for(; hash[awesomenessLevel+3] == 0 && awesomenessLevel < hash.length; ++awesomenessLevel);
            switch(awesomenessLevel){
                case 0: 
                    System.out.println("You have no zero byte computed, ok, maybe next time");
                    break;
                case 1: 
                    System.out.println("Congratulations! You have 1 extra zero byte");
                    break;
                case 2: 
                    System.out.println("Wow! 2 extra zero bytes, awesome!");
                    break;
                default: 
                    System.out.println("This is insane! You have 3+ extra zero bytes. Coool!");
                    break;
            }
        } else {
            System.out.println(String.format(
                    "Sorry, solution is not correct. Input hash string [%s] result digest [%s] %s",
                    msg.getHashInput(), Globals.bytesToHex(hash), uco.substring(0, 2)));
        }
    }
}
