/*
    Chinmay Garg
    CMPSC 443 - Lab 1 
    Double DES implementation - Man in the middle attack
    File 1 - DoubleDES (current)
    File 2 - Meet in the Middle
 */

//remember to remove this part to compile through terminal

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.security.*;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;
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

    //default constructor that takes in the secret keys and initializes into encrypt and decrypt mode
    //applies the required padding to each Cipher
    //thats why I made 4 ciphers so I don't need to worry about reusing and reinitializing them
    //correctly when required, this way they are always correct
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

    
    //Encrypts the given plaintext into cipherText using the keys given
    //DoubleDES uses two SecretKeys so this is done by applying two ciphers
    public String encrypt(String plaintext) throws UnsupportedEncodingException, IllegalBlockSizeException, BadPaddingException 
    {

        //byte[] plain = DatatypeConverter.parseHexBinary(plaintext);
        
        //System.out.println("PlainText : "+ plaintext);
        byte[] plain = DatatypeConverter.parseHexBinary(plaintext);
        
        byte[] ciphertext = c1.doFinal(plain);
        byte[] cipherfinal = c2.doFinal(ciphertext);

        return DatatypeConverter.printHexBinary(cipherfinal);
    }


    //Decrypts the given ciphertext into plaintext using the keys given in reverse order
    //decrypts with key2 and then key1 if encrypted otherwise
    //converts into string and then returns it
    //converting into lowercase into the main function since not sure if the grader wants lower or upper case hex
    public String decrypt(String ciphertext) throws IOException, IllegalBlockSizeException, BadPaddingException{
        byte[] cipher = DatatypeConverter.parseHexBinary(ciphertext);
       
        byte[] plaintext = c3.doFinal(cipher);
        byte[] plainfinal = c4.doFinal(plaintext);

        //return new String(plainfinal, "UTF-8");
        
        return DatatypeConverter.printHexBinary(plainfinal);

    }

	
	
    public static void main(String[] args) throws NoSuchAlgorithmException, InvalidKeyException, UnsupportedEncodingException, IllegalBlockSizeException, BadPaddingException, IOException, InvalidKeySpecException {

        //converting into bigInteger since it is a Hex string too big for normal int
        BigInteger bits = new BigInteger(args[0],16);
        
       // String bitString = bits.toString(16);

        //creating a byte array to store the key given
        byte[] inputKey = new byte [16];
        
        //not sure about this 
        //UPDATE: Works and required! Approved by TA
        inputKey = DatatypeConverter.parseHexBinary(args[0]);
        
        //this will store the bytes for the thing into the inputKey
        //inputKey = args[0].getBytes();
        //creating a string to make a binary string of the given Hex key
        String bitString = "";
        for(int i =0; i< inputKey.length;i++)
        {
            byte b1 = inputKey[i];
            bitString += String.format("%8s",Integer.toBinaryString(b1 & 0xFF)).replace(' ','0');  
        }
        
        //System.out.println(bitString);
        
        
        //Will go through the entire length of the key given BEFORE splitting
        //will take every 7 bits and add parity bit to create a new string with 
        //enough bits to split them into two parts
        //and then into 8 groups
        //and then those two keys will later be converted into SecretKey using the code provided on Piazza
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
        //deal with sign byte
        if(inputKey.length > 16){
        inputKey = Arrays.copyOfRange(inputKey,1, inputKey.length);
        }
        
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

        
        //creating a class variable and then initializing the Ciphers
        //using the keys we just generated
        DoubleDES crypt2 = new DoubleDES(secretKeyA, secretKeyB);
        
        //System.out.println("Encrypted Text: " + crypt2.encrypt(args[1]).toLowerCase());
       
        //calling the encrypt function and then converting into lowercase
        //because the output in the description on canvas was in lowercase
        System.out.println(crypt2.encrypt(args[1]).toLowerCase());
        
        /*
        Gives the original string with the decrypt function
        ONLY FOR TESTING
        Commented it out because not needed as a part of the output
        but feel free to use it to test
        */  
        
        
        //System.out.println(crypt2.decrypt(crypt2.encrypt(args[1])));

        
        //Thank you for helping me out in your Office today. That really helped me figure it out.
    }
    
}
