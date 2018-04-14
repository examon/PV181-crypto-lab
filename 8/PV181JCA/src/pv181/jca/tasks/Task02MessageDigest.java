/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package pv181.jca.tasks;

import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import javax.xml.bind.DatatypeConverter;
import pv181.jca.Globals;

/**
 *
 * @author dusanklinec
 */
public class Task02MessageDigest {
    public static void main(String args[]) throws IOException, NoSuchAlgorithmException {
        byte[] expectedMd5 = DatatypeConverter.parseHexBinary("e64db39c582fe33b35df742e8c23bd55");

        // 1. Obtain InputStream for web page - follow hint.
        final InputStream is01 = new URL(
                "http://www.fi.muni.cz/~xklinec/java/file_a.bin"
        ).openStream();
        
        // 2. Obtain MessageDigest instances. 
        MessageDigest md5 = MessageDigest.getInstance("MD5");
        MessageDigest sha256 = MessageDigest.getInstance("sha-256");
        
        // 3. Read InputStream iterativelly.
        // In each iteration update the internal state of the MessageDigest
        // Allocate a temporary buffer to read data to.
        byte[] buffer = new byte[1024];

        // Read input stream by chunks.
        int bytesRead = -1;
        while ((bytesRead = is01.read(buffer)) >= 0){
                // buffer now contains bytesRead bytes of data, process it.	
                // Pay attention to a fact that read() call does not necessarily 
                // have to fill the whole buffer with a valid data!

                // TODO: do some work here.
                // e.g., update digest state, process with cipher, etc...
                //System.out.println(bytesRead);
                //System.err.println(Globals.bytesToHexString(buffer));
                md5.update(buffer, 0, bytesRead);
                sha256.update(buffer, 0, bytesRead);
        }

        // Stream reading finished here.
        // Since bytesRead contains negative value it means there is no more data
        // in the stream.
        // 4. Compute final message digest and print it.
        byte[] digest = md5.digest();
        byte[] digest1 = sha256.digest();
                

        // 5. Find a difference between provided digests and computed.
        System.out.println(Globals.bytesToHexString(digest));
        System.out.println(Globals.bytesToHexString(expectedMd5));     
        
    }
}
