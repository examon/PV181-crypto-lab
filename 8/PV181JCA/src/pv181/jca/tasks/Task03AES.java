/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package pv181.jca.tasks;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;
import pv181.jca.Globals;

/**
 *
 * @author dusanklinec
 */
public class Task03AES {
    public static void main(String args[]) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
        /**
         * Hint 1: In order to construct a String from byte[] buffer call new String(buffer);
         */
        // 1. Obtain a Cipher instance with given parameters as specified on the web.
        Cipher aes = Cipher.getInstance("AES/CBC/PKCS5Padding");
        byte[] key = DatatypeConverter.parseBase64Binary("AAAAAAAAAAAAAAAAAAAAAA==");
        byte[] iv = DatatypeConverter.parseBase64Binary("AAAAAAAAAAAAAAAAAAAAAA==");
 
        
        // 2. Call cipher.init with suitable parameters. Use Cipher.DECRYPT_MODE
        // as a first parameter of init. 
        aes.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"), new IvParameterSpec(key) );
        
        // 3.  Convert base64 data from the website (IV, KEY, CIPHERTEXT)
        // to the byte[] with DatatypeConverter class.
        byte[] plaintext = aes.doFinal(DatatypeConverter.parseBase64Binary("6VMSY9xFduwNsiyn8mGZdLG6/NXb3ziw81MBSfaKozs="));
        System.out.println(new String(plaintext));
        // 4. Call cipher.doFinal on the data from website.
        // ...
        
        // 5. Print result of doFinal method as a string.
        // ...
        
    }
}
