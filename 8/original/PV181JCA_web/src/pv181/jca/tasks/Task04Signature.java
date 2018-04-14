package pv181.jca.tasks;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.security.Signature;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import javax.xml.bind.DatatypeConverter;

/**
 *
 * @author dusanklinec
 */
public class Task04Signature {
    public static void main(String args[]) throws Exception{
        // Create instance of the signature object (for both sign & verify)
        Signature sig = Signature.getInstance("SHA1WithRSA");
        
        // For verification we need public key. It is stored in the certificate.
        // The first step is to open stream to the certificate
        String certUrl = "http://www.fi.muni.cz/~xklinec/java/crt.der";
        InputStream certIs = new URL(certUrl).openStream();
        
        // Open certificate stream and load the certificate 
        CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
        X509Certificate certNew = 
                (X509Certificate)certFactory.generateCertificate(certIs);
        
        // Dump certificate structure to the stdout.
        System.out.println(certNew);
        
        // Initialize verifier with the public key stored in the certificate
        sig.initVerify(certNew.getPublicKey());
        
        // Open stream with the first file to verify
        String fileUrl = "http://www.fi.muni.cz/~xklinec/java/file_a.bin";
        InputStream fileIs = new URL(fileUrl).openStream();
        
        // Verify big file on the fly - iterative approach
	byte[] buffer = new byte[2048];
	int nread = fileIs.read(buffer);
	while (nread > 0) {
		sig.update(buffer, 0, nread);
		nread = fileIs.read(buffer);
	}
           
        // Now download claimed signature from the web.
        String sigUrl = "http://www.fi.muni.cz/~xklinec/java/file_a.sig";
        InputStream sigIs = new URL(sigUrl).openStream();
        
        // Read the whole stream to bytes, watch out, it is base64 encoded
        byte[] sigBuff = inputStreamToByte(sigIs);
        sigBuff = DatatypeConverter.parseBase64Binary(new String(sigBuff));
        
        // Verify the signature
        boolean success = sig.verify(sigBuff);
        if (success){
            System.out.println("Verification successfull!");
        } else {
            System.err.println("Signature verification failed!");
        }
    }
    
    public static byte[] inputStreamToByte(InputStream is) throws IOException{
	ByteArrayOutputStream buffer = new ByteArrayOutputStream();

	int nRead;
	byte[] data = new byte[16384];
	while ((nRead = is.read(data, 0, data.length)) != -1) {
	  buffer.write(data, 0, nRead);
	}

	buffer.flush();

	return buffer.toByteArray();
    }
}
