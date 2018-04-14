/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package pv181.jca.homework;

import com.google.protobuf.ByteString;
import java.io.FileNotFoundException;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.SignatureException;
import java.util.ArrayList;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;
import pv181.jca.Globals;
import pv181.jca.protobuf.entities.Messages;

class MyRunnable implements Runnable {
    BigInteger start;
    private int id;
    BigInteger step;

    public MyRunnable(int id, BigInteger start, BigInteger step) {
        this.start = start;
        this.id = id;
        this.step = step;
    }

    public void run() {
        System.out.println(String.format("%d: %s-%s", this.id, this.start.toString(), this.start.add(this.step)).toString());

        MessageDigest sha256 = null;
        try {
            sha256 = MessageDigest.getInstance("sha-256");
        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(MyRunnable.class.getName()).log(Level.SEVERE, null, ex);
        }

        String uco = "422336";
        byte[] digest;
        String res;
        BigInteger max = this.start.add(step);
        BigInteger c = this.start;

        while (true) {
            sha256.reset();
            c = c.add(BigInteger.ONE);
            if (c.compareTo(max) > 0) {
                System.out.println(String.format("%d: END", this.id));
                return;
            }
            res = String.format("%s:%s", uco, c.toString());
            //System.out.println(res);
            sha256.update(res.getBytes());
            digest = sha256.digest();

            if (uco.substring(0, 2).equalsIgnoreCase(String.format("%02x", digest[0]))
                    && uco.substring(2, 4).equalsIgnoreCase(String.format("%02x", digest[1]))
                    && uco.substring(4, 6).equalsIgnoreCase(String.format("%02x", digest[2]))
                    && (digest[3] == 0))
            {
                System.out.println("---");
                System.out.println(String.format("%d: %s", this.id, this.start.toString()));
                System.out.println(res);
                System.out.println(Globals.bytesToHexString(digest));
                System.out.println("---");
                break;
            }
        }

    }
}

public class HashCollisions {

    public static void main(String args[]) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException, SignatureException, FileNotFoundException {        
        /* Uncomment to start hash computation
        BigInteger start = new BigInteger("0");
        BigInteger step = new BigInteger("100000000");
        int id = 0;
        final int max_threads = 8;
        ArrayList<Thread> pool = new ArrayList();
                
        while (true) {
            for (int j = 0; j < pool.size(); j++) {
                if (pool.get(j).isAlive() == false) {
                    pool.remove(j);
                }
            }
            if (pool.size() <= max_threads) {
                MyRunnable myRunnable = new MyRunnable(id, start, step);
                id += 1;
                start = start.add(step);
                Thread t = new Thread(myRunnable);
                pool.add(t);
                t.start();
            }
        }
        */
               
        // Compute digest
        MessageDigest sha256 = MessageDigest.getInstance("sha-256");
        String uco = "422336";
        //String res = "422336:549694887"; // digest[3] == upper half 0
        String res = "422336:3493409012"; // digest[3] == 0x00
        byte[] digest;
        sha256.update(res.getBytes());
        digest = sha256.digest();

        // debug
        {
            System.out.println("DONE");
            System.out.println(res);
            System.out.println(Globals.bytesToHexString(digest));
        }

        // Part 1 - build a new protobuf message.
        Messages.HashMessage.Builder builder = Messages.HashMessage.newBuilder();

        // Put values to the builder.
        builder.setUco(uco); // TODO: change to your UCO.
        builder.setHashType(1); // Constant, leave 1.
        builder.setHashInput(res); // TODO: add given input hash you found.
        builder.setHash(ByteString.copyFrom(digest)); // Result digest.

        // TODO: compute HMAC, AES, RSA, Signature on "digest".
        // AES - encrypt digest.
        Cipher aes = Cipher.getInstance("AES/CBC/PKCS5Padding");
        byte[] key = new byte[16];
        byte[] iv = new byte[16];
        SecureRandom rand = new SecureRandom();

        rand.nextBytes(iv);
        rand.nextBytes(key);

        builder.setAesIv(ByteString.copyFrom(iv));
        builder.setAesKey(ByteString.copyFrom(key));

        aes.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), new IvParameterSpec(iv));
        byte[] ciphertext = aes.doFinal(digest);
        builder.setAesCiphertext(ByteString.copyFrom(ciphertext));

        //* debug
        {
            aes.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"), new IvParameterSpec(iv));
            byte[] plaintext = aes.doFinal(ciphertext);
            System.out.println("AES begin ---");
            System.out.println("AES iv \n" + Globals.bytesToHexString(iv));
            System.out.println("AES key: \n" + Globals.bytesToHexString(key));
            System.out.println("AES ciphertext: \n" + Globals.bytesToHexString(ciphertext));
            System.out.println("AES plaintext: \n" + Globals.bytesToHexString(plaintext));
            System.out.println("AES end ---");
        }
        //*/

        // RSA - encrypt digest.
        Cipher rsa = Cipher.getInstance("RSA/ECB/PKCS1PADDING");
        // Generate public,private key pair.
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(8192);
        KeyPair kp = kpg.generateKeyPair();
        PrivateKey aPrivate = kp.getPrivate();
        PublicKey aPublic = kp.getPublic();
        // Set generated key pair to the message so we can verify your result.
        builder.setPrivateKey(ByteString.copyFrom(Globals.serializeKey(aPrivate)));
        builder.setPublicKey(ByteString.copyFrom(Globals.serializeKey(aPublic)));

        rsa.init(Cipher.ENCRYPT_MODE, aPublic);
        byte[] rsaCipher = rsa.doFinal(digest);
        builder.setRsaCiphertext(ByteString.copyFrom(rsaCipher));

        
        //* debug
        {
            rsa.init(Cipher.DECRYPT_MODE, aPrivate);
            byte[] rsaPlaintext = rsa.doFinal(rsaCipher);
            System.out.println("RSA start ---");
            System.out.println("RSA rsaCipher \n" + Globals.bytesToHexString(rsaCipher));
            System.out.println("RSA rsaPlaintext \n" + Globals.bytesToHexString(rsaPlaintext));
            System.out.println("RSA end ---");
        }
        //*/
        

        // RSA Signature - sign digest.
        java.security.Signature sig = java.security.Signature.getInstance("SHA1WithRSA");
        sig.initSign(aPrivate);
        sig.update(digest);
        byte[] rsaSign = sig.sign();
        builder.setRsaSignature(ByteString.copyFrom(rsaSign));
        //builder.setRsaSignature(ByteString.copyFrom(Globals.serializeKey(rsaSign)));
        
        //* debug
        {
            java.security.Signature signer = java.security.Signature.getInstance("SHA1withRSA");
            signer.initVerify(aPublic);
            signer.update(digest);
            boolean rsaVerify = signer.verify(rsaSign);
            System.out.println("RSA SIGN start ---");
            System.out.println("RSA SIGN rsaSign \n" + Globals.bytesToHexString(rsaSign));
            System.out.println("RSA SIGN rsaVerify: " + String.format("%b\n", rsaVerify));
            System.out.println("RSA SIGN end ---");
        }
        //*/
        
    
        // HMAC - hmac digest.
        Mac mac = Mac.getInstance("HmacSHA1");
        // Generate a random hmac key. store it to the message.
        byte[] rand_key = new byte[16];
        rand.nextBytes(rand_key);
        SecretKeySpec hmackey = new SecretKeySpec(rand_key, "HmacSHA1");
        mac.init(hmackey);
        byte[] hmac = mac.doFinal(digest);
        
        builder.setHmacKey(ByteString.copyFrom(hmackey.getEncoded()));
        // Generate hmac on digest and store it to the message.
        builder.setHmac(ByteString.copyFrom(hmac));

        //* debug
        {
            System.out.println("HMAC start ---");
            System.out.println("HMAC rand_key\n" + Globals.bytesToHexString(rand_key));
            System.out.println("HMAC hmackey\n" + Globals.bytesToHexString(hmackey.getEncoded()));
            System.out.println("HMAC hmac\n" + Globals.bytesToHexString(hmac));
            System.out.println("HMAC end ---\n");
        }
        //*/
        
        
        // Build the final message.
        Messages.HashMessage msg = builder.build();

        // Print encoded message
        System.out.println("Demo message: " + msg.toString());
        byte[] msgCoded = msg.toByteArray();
        final String msgBase64encoded = DatatypeConverter.printBase64Binary(msgCoded);
        System.out.println(msgBase64encoded);
        // TODO: save msgBase64encoded to the uco_hash.txt, ZIP it together with the source file
        // and submit to IS.
        
        try(PrintWriter out = new PrintWriter("422336_hash.txt")){
            out.print(msgBase64encoded);
        }

        // You can verify your result by calling the following function:
        verify(msgBase64encoded);
    }

    /**
     * Function provided to verify your result. Warning! This method does not
     * verify correctness of the HMAC, AES, RSA & Signature values.
     *
     * @param encoded
     */
    public static void verify(String encoded) throws NoSuchAlgorithmException {
        Messages.HashMessage msg = null;
        System.out.println("=================================================");
        System.out.println("Result verification started\n");
        try {
            msg = Messages.HashMessage.parseFrom(DatatypeConverter.parseBase64Binary(encoded));
            System.out.println("Reconstructed message: " + msg);

            if (msg == null) {
                throw new IllegalArgumentException("Reconstructed message is null!");
            }

            if (msg.getHash() == null || msg.getUco() == null || msg.getHashInput() == null) {
                throw new IllegalArgumentException("Some of the message field is null!");
            }
        } catch (Exception ex) {
            System.out.println("Exception! Message is not properly formatted.");
            ex.printStackTrace();
            return;
        }

        final String uco = msg.getUco();

        // Check format
        if (uco.length() < 6) {
            throw new IllegalArgumentException("Your UCO has invalid format: " + uco);
        }

        if (msg.getHashInput().startsWith(uco) == false) {
            throw new IllegalArgumentException("Your hash input string is not of a valid format " + msg.getHashInput());
        }

        byte[] hash = MessageDigest.getInstance("SHA-256").digest(msg.getHashInput().getBytes());

        if (uco.substring(0, 2).equalsIgnoreCase(String.format("%02x", hash[0]))
                && uco.substring(2, 4).equalsIgnoreCase(String.format("%02x", hash[1]))
                && uco.substring(4, 6).equalsIgnoreCase(String.format("%02x", hash[2]))
                && (hash[3] & ((byte) 0xF0)) == 0) {
            System.out.println(String.format("Your solutions seems correct (if your UCO is %s)! Congrats. Hash:\n%s", uco, Globals.bytesToHexString(hash)));
            int awesomenessLevel = 0;
            for (; hash[awesomenessLevel + 3] == 0 && awesomenessLevel < hash.length; ++awesomenessLevel);
            switch (awesomenessLevel) {
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
                    msg.getHashInput(), Globals.bytesToHexString(hash), uco.substring(0, 2)));
        }
    }
}
