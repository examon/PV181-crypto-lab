package pv181.jca.protobuf;

import com.google.protobuf.ByteString;
import com.google.protobuf.InvalidProtocolBufferException;
import javax.xml.bind.DatatypeConverter;
import pv181.jca.protobuf.entities.Messages;

/**
 *
 * @author dusanklinec
 */
public class ProtobufDemo {
    public static void main(String args[]) throws InvalidProtocolBufferException {
        // Initialize values you want to serialize.
        int intVal = 42;
        String demoText = "demo text"; 
        byte[] byteVal = new byte[] {(byte)0x12, (byte)0x34, (byte)0x56, (byte)0x78, (byte)0x90};
        
        // Part 1 - build a new protobuf message.
        Messages.DemoMessage.Builder builder = Messages.DemoMessage.newBuilder();
        // Put values to the builder.
        builder.setIntegerField(intVal);
        builder.setStringField(demoText);
        builder.setByteField(ByteString.copyFrom(byteVal));
        // Build the final message.
        Messages.DemoMessage msg = builder.build();
        
        System.out.println("Demo message: " + msg.toString());
        byte[] msgCoded = msg.toByteArray();
        final String msgBase64encoded = DatatypeConverter.printBase64Binary(msgCoded);
        
        // Transfer message over channel.
        // In this form you will submit your assignments.
        System.out.println("Demo message encoded: " + msgBase64encoded);
        
        // Part 2 - decode protocol buffers message.
        byte[] msgCoded2 = DatatypeConverter.parseBase64Binary(msgBase64encoded);
        Messages.DemoMessage reconstructedMsg = Messages.DemoMessage.parseFrom(msgCoded2);
        System.out.println("Reconstructed message: " + reconstructedMsg);
    }
}
