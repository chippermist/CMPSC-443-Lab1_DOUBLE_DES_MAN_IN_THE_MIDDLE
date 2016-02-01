/*
    Chinmay Garg
    CMPSC 443 - Lab 1 
    Double DES implementation - Man in the middle attack
 */
package lab1doubledes;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.security.*;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.*;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.DESKeySpec;
import java.util.Scanner;
import javax.xml.bind.DatatypeConverter;
import static javax.xml.bind.DatatypeConverter.parseHexBinary;
import sun.security.util.BitArray;
/**
 *
 * @author chinmaygarg
 */
public class DoubleDES {

    /**
     * @param args the command line arguments
     */
    
    Cipher c1;
    Cipher c2;
    Cipher c3;
    Cipher c4;

    DoubleDES(SecretKey key1, SecretKey key2) throws InvalidKeyException, NoSuchAlgorithmException 
    {
        try {
            c1 = Cipher.getInstance("DES/ECB/PKCS5Padding");
        } catch (NoSuchPaddingException ex) {
            Logger.getLogger(DoubleDES.class.getName()).log(Level.SEVERE, null, ex);
        }
        
        
        try {
            c2 = Cipher.getInstance("DES/ECB/NoPadding");
        } catch (NoSuchPaddingException ex) {
            Logger.getLogger(DoubleDES.class.getName()).log(Level.SEVERE, null, ex);
        }
        
                try {
            c4 = Cipher.getInstance("DES/ECB/PKCS5Padding");
        } catch (NoSuchPaddingException ex) {
            Logger.getLogger(DoubleDES.class.getName()).log(Level.SEVERE, null, ex);
        }
        
        
        try {
            c3 = Cipher.getInstance("DES/ECB/NoPadding");
        } catch (NoSuchPaddingException ex) {
            Logger.getLogger(DoubleDES.class.getName()).log(Level.SEVERE, null, ex);
        }

            c1.init(Cipher.ENCRYPT_MODE, key1);
            c2.init(Cipher.ENCRYPT_MODE, key2);

            c3.init(Cipher.DECRYPT_MODE, key2);
            c4.init(Cipher.DECRYPT_MODE, key1);
    }

    public String encrypt(String plaintext) throws UnsupportedEncodingException, IllegalBlockSizeException, BadPaddingException 
    {

        //byte[] plain = DatatypeConverter.parseHexBinary(plaintext);
        
        byte[] plain = plaintext.getBytes("UTF-8");
        
        byte[] ciphertext = c1.doFinal(plain);
        byte[] cipherfinal = c2.doFinal(ciphertext);

        return new sun.misc.BASE64Encoder().encode(cipherfinal);
    }


    public String decrypt(String ciphertext) throws IOException, IllegalBlockSizeException, BadPaddingException{
        byte[] cipher = new sun.misc.BASE64Decoder().decodeBuffer(ciphertext);
       
        byte[] plaintext = c3.doFinal(cipher);
        byte[] plainfinal = c4.doFinal(plaintext);

        return new String(plainfinal, "UTF-8");

    }

	
	
    public static void main(String[] args) throws NoSuchAlgorithmException, InvalidKeyException, UnsupportedEncodingException, IllegalBlockSizeException, BadPaddingException, IOException, InvalidKeySpecException {

//        for(int i =0; i< args.length; i++){
//            System.out.println(args[i]);
//        }
        

        BigInteger bits = new BigInteger(args[0],16);
        
        String bitString = bits.toString(2);
        
        System.out.println("Original bit String: " + bitString);
        
        //String[] keys = null;

//        for(int i =0; i< bitString.length(); i++)
//        {
//            
//           for(int j = 0; j<bitString.length();j+=6)
//           {
//             
//              
//           }
//        }
        
        
        
        KeyGenerator keygen1 = KeyGenerator.getInstance("DES");
        SecretKey desKey1 = keygen1.generateKey();
        KeyGenerator keygen2 = KeyGenerator.getInstance("DES");
        SecretKey desKey2 = keygen1.generateKey();
        DoubleDES crypt1 = new DoubleDES(desKey1, desKey2);
        
        System.out.println("Plain Text: " + args[1]);
        
        
        String encryptedText = crypt1.encrypt(args[1]);
        System.out.println("Encrypted Text: " + encryptedText);
        
        String decryptedText = crypt1.decrypt(encryptedText);
        System.out.println("Decrypted Text: " + decryptedText);

        //byte[] first = key1.getBytes();
        //byte[] second = key2.getBytes();
/*
        byte[] arg1 = new byte [14];
        //arg1 = args[0].getBytes();
        arg1 = parseHexBinary(args[0]);
        //        for(int i =0; i< arg1.length; i++){
        //            System.out.println(arg1[i]);
        //        }
        byte[] key1 = new byte[7];
        byte[] key2 = new byte[7];
        System.arraycopy(arg1, 0, key1, 0, 7);
        System.arraycopy(arg1, 7, key2, 0, 7);
        //System.out.println(key1[0]);
        int a = key1[0];
        //System.out.println(Integer.toBinaryString(key1[0]));
        //        System.out.println("Hello this is the first key");
        //        for(int i =0; i< key1.length; i++){
        //            System.out.println(key1[i]);
        //        }
        // DESKeySpec keySpecEncrypt1 = new DESKeySpec(key1);
        // SecretKeyFactory keyFactory1 = SecretKeyFactory.getInstance("DES");
        // SecretKey secretKey1 = keyFactory1.generateSecret(keySpecEncrypt1);
        // DESKeySpec keySpecEncrypt2 = new DESKeySpec(key2);
        // SecretKeyFactory keyFactory2 = SecretKeyFactory.getInstance("DES");
        // SecretKey secretKey2 = keyFactory2.generateSecret(keySpecEncrypt2);
        KeyGenerator keygen1 = KeyGenerator.getInstance("DES");
        SecretKey desKey1 = keygen1.generateKey();
        KeyGenerator keygen2 = KeyGenerator.getInstance("DES");
        SecretKey desKey2 = keygen1.generateKey();
        DoubleDES crypt1 = new DoubleDES(desKey1, desKey2);
        byte[] encryptedText = crypt1.encrypt(args[1]);
        System.out.println(encryptedText.toString());
        byte[] decryptedText = crypt1.decrypt(encryptedText.toString());
        System.out.println(decryptedText.toString());
         */



       
    }
    
}
