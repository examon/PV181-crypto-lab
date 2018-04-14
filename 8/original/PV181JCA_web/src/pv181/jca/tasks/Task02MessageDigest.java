package pv181.jca.tasks;

import java.io.InputStream;
import java.net.URL;
import java.security.MessageDigest;
import pv181.jca.Globals;

/**
 *
 * @author dusanklinec
 */
public class Task02MessageDigest {
    public static void main(String args[]) throws Exception {
        
        InputStream is01 = new URL("http://www.fi.muni.cz/~xklinec/java/file_a.bin").openStream();
        byte[] buffer = new byte[1024];
        
        MessageDigest md5 = MessageDigest.getInstance("MD5");
        MessageDigest sha = MessageDigest.getInstance("SHA-256");
        
        int bytesRead = -1;
        while ((bytesRead = is01.read(buffer)) >= 0){
            md5.update(buffer, 0, bytesRead);
            sha.update(buffer, 0, bytesRead);
        }
        
        System.out.println(Globals.bytesToHex(md5.digest(), false));
        System.out.println(Globals.bytesToHex(sha.digest(), false));
    }
}
