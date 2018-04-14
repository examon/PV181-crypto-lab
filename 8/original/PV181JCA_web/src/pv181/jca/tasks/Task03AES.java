package pv181.jca.tasks;

import java.security.Key;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;
import pv181.jca.Globals;

/**
 *
 * @author dusanklinec
 */
public class Task03AES {
    public static void main(String args[]) throws Exception {
        byte[] key = DatatypeConverter.parseBase64Binary(
                "AAAAAAAAAAAAAAAAAAAAAA==");
        byte[] iv = DatatypeConverter.parseBase64Binary(
                "AAAAAAAAAAAAAAAAAAAAAA==");
        byte[] ciphertext = DatatypeConverter.parseBase64Binary(
                "6VMSY9xFduwNsiyn8mGZdLG6/NXb3ziw81MBSfaKozs=");
        
        Cipher aes = Cipher.getInstance("AES/CBC/PKCS5Padding");
        
        Key aesKey = new SecretKeySpec(key, "AES");
        aes.init(Cipher.DECRYPT_MODE, aesKey, new IvParameterSpec(iv));
        
        byte[] plaintext = aes.doFinal(ciphertext);
        System.out.println(Globals.bytesToHex(plaintext, false));
        System.out.println(new String(plaintext));
    }
}
