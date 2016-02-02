/*
    Chinmay Garg
    CMPSC 443 - Lab 1 
    Double DES implementation - Man in the middle attack
 */

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
import javax.crypto.SecretKey;
import javax.crypto.spec.DESKeySpec;
import javax.xml.bind.DatatypeConverter;
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
        
        //System.out.println("PlainText : "+ plaintext);
        byte[] plain = DatatypeConverter.parseHexBinary(plaintext);
        
        byte[] ciphertext = c1.doFinal(plain);
        byte[] cipherfinal = c2.doFinal(ciphertext);

        return DatatypeConverter.printHexBinary(cipherfinal);
    }


    public String decrypt(String ciphertext) throws IOException, IllegalBlockSizeException, BadPaddingException{
        byte[] cipher = DatatypeConverter.parseHexBinary(ciphertext);
       
        byte[] plaintext = c3.doFinal(cipher);
        byte[] plainfinal = c4.doFinal(plaintext);

        //return new String(plainfinal, "UTF-8");
        
        return DatatypeConverter.printHexBinary(plainfinal);

    }

	
	
    public static void main(String[] args) throws NoSuchAlgorithmException, InvalidKeyException, UnsupportedEncodingException, IllegalBlockSizeException, BadPaddingException, IOException, InvalidKeySpecException {


        BigInteger bits = new BigInteger(args[0],16);
        
       // String bitString = bits.toString(16);

        
        byte[] inputKey = new byte [14];
        
        //not sure about this
        inputKey = DatatypeConverter.parseHexBinary(args[0]);
        
        //this will store the bytes for the thing into the inputKey
        //inputKey = args[0].getBytes();
        String bitString = "";
        for(int i =0; i< inputKey.length;i++)
        {
            byte b1 = inputKey[i];
            bitString += String.format("%8s",Integer.toBinaryString(b1 & 0xFF)).replace(' ','0');  
        }
        
        //System.out.println(bitString);
        
       
        
        String temp = "";
        for(int i =0 ; i < bitString.length(); i+=7)
        {
            int ones = 0; 
            for(int j = i; j < i+7; j++)
            {
                if(bitString.charAt(j) ==  '1')
                {
                    ones++;
                }
                    
                temp += bitString.charAt(j);
            }
            
            if(ones % 2 == 0)
            {
                temp += "1";
            }
            else
            {
                temp += "0";
            }
            
           
            
            
        }
        //System.out.println("Parity String"+ temp);
        
  
        inputKey = new BigInteger(temp, 2).toByteArray();
        
        byte[] key1 = new byte[8];
        byte[] key2 = new byte[8];
        
        System.arraycopy(inputKey, 0, key1, 0, 8);
        System.arraycopy(inputKey, 8, key2, 0, 8);
        
        //System.out.print(DatatypeConverter.printHexBinary(key1));

        //part where the Key is generated
        
        DESKeySpec keySpecEncryptA = new DESKeySpec(key1);
        SecretKeyFactory keyFactoryA = SecretKeyFactory.getInstance("DES");
        SecretKey secretKeyA = keyFactoryA.generateSecret(keySpecEncryptA);
        
        
        DESKeySpec keySpecEncryptB = new DESKeySpec(key2);
        SecretKeyFactory keyFactoryB = SecretKeyFactory.getInstance("DES");
        SecretKey secretKeyB = keyFactoryB.generateSecret(keySpecEncryptB);

        DoubleDES crypt2 = new DoubleDES(secretKeyA, secretKeyB);
        
        //System.out.println("Encrypted Text: " + crypt2.encrypt(args[1]).toLowerCase());
        System.out.println(crypt2.encrypt(args[1]).toLowerCase());
        
        //System.out.println("Decrypted Text: " + crypt2.decrypt(crypt2.encrypt(args[1])));
       
    }
    
}
