/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package pv181.jca.tasks;

import java.security.NoSuchAlgorithmException;
import javax.crypto.Cipher;

/**
 *
 * @author dusanklinec
 */
public class Task00AESStrength {
    public static void main(String args[]) throws NoSuchAlgorithmException {
        /**
         * Hint 1: Use CTRL+SHIFT+I to automatically add missing imports.
         * Hint 2: Use System.out.printn("TEST"); in order to print something on the terminal.
         * Hint 3: In order to execute code in this file, right click on a file 
         * in the left panel and select "Run".
         */
        
        System.out.println("Maximum allowed AES key size is " + 
                Cipher.getMaxAllowedKeyLength("AES"));
        
    }   
}
