/*
    Chinmay Garg
    CMPSC 443 - Lab 1 
    Double DES implementation - Man in the middle attack
    File 1 - DoubleDES
    File 2 - Meet in the Middle (current)
 */

/**
 *
 * @author chinmaygarg
 */

//remember to remove this part, won't compile through terminal

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.math.*;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.*;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESKeySpec;
import javax.xml.bind.DatatypeConverter;

/**
 *
 * @author chinmaygarg
 */
public class MeetInMiddle {
    
    Cipher c1;
    Cipher c2;
    
    MeetInMiddle() {}
        
    //Because java was being a bitch
    MeetInMiddle(SecretKey key1, SecretKey key2) throws NoSuchAlgorithmException, InvalidKeyException
    {
        //trying to use padding for encryption and noPadding for decryption
        try {
            c1 = Cipher.getInstance("DES/ECB/PKCS5Padding");
        } catch (NoSuchPaddingException ex) {
            Logger.getLogger(MeetInMiddle.class.getName()).log(Level.SEVERE, null, ex);
        }
        
        try {
            c2 = Cipher.getInstance("DES/ECB/NoPadding");
        } catch (NoSuchPaddingException ex) {
            Logger.getLogger(MeetInMiddle.class.getName()).log(Level.SEVERE, null, ex);
        }

        //initializing for encrypting
        c1.init(Cipher.ENCRYPT_MODE, key1);
        //initializing for decrypting
        c2.init(Cipher.DECRYPT_MODE, key2);
        
        
    }
    

    
    //similar to the function in DoubleDES apart from that it only does on one key
   public String encrypt(String plaintext) throws UnsupportedEncodingException, IllegalBlockSizeException, BadPaddingException 
    {

        //byte[] plain = DatatypeConverter.parseHexBinary(plaintext);
        
        //System.out.println("PlainText : "+ plaintext);
        byte[] plain = DatatypeConverter.parseHexBinary(plaintext);
        
        byte[] ciphertext = c1.doFinal(plain);

        return DatatypeConverter.printHexBinary(ciphertext);
    }

   //similar to the function in DoubleDES apart from that it does on one key
    public String decrypt(String ciphertext) throws IOException, IllegalBlockSizeException, BadPaddingException{
        
        //converts the cipherText into bytes
        byte[] cipher = DatatypeConverter.parseHexBinary(ciphertext);
       
        byte[] plaintext = c2.doFinal(cipher);
        
        //returns a string. Shown how to do by the TA for part1, reused in part2
        return DatatypeConverter.printHexBinary(plaintext);

    }
    
    //doing bit parity similar to part1
    //Converting the entire string of Hex into binary representation
    //found how to do the bit conversion without losing zeros on Stack Overflow
    //link: http://stackoverflow.com/questions/12310017/how-to-convert-a-byte-to-its-binary-string-representation
    //the function takes in that binary string, and pulls 7 blocks of bits and then adds the parity bit 
    //creatig a new string called temp
    
    public static final byte[] parityBitting(String byteString){
       
        byte[] inputKey = new byte [8];
        
        //not sure about this
        inputKey = DatatypeConverter.parseHexBinary(byteString);
        
        //this will store the bytes for the thing into the inputKey
        //inputKey = args[0].getBytes();
        String bitString = "";
        for(int i =0; i< inputKey.length;i++)
        {
            byte b1 = inputKey[i];
            //cited above
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
            
            
            //basic modular function to decide which parity bit needs to be added
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
        
        //converting back into the byte[] array to return back
        inputKey = new BigInteger(temp, 2).toByteArray();
        
        //deal with sign byte
        if(inputKey.length>8){
        inputKey = Arrays.copyOfRange(inputKey,1, inputKey.length);
        }
        
        return inputKey;
    }
    
    
    public void MiM(String plainText, String cipherText) throws NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException, UnsupportedEncodingException, IllegalBlockSizeException, BadPaddingException, IOException{
        

        
        //contains all the possible keys of the hex that are possible
        String[] HEX = {"0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "a", "b", "c", "d", "e", "f"};
        
        //creating a hash table to store the keys for faster access in O(1)
        //Hashtable hashTable = new Hashtable();
        
        //Now using HashMap since it kept giving obsolete reference
        //Realized this is better and has all the same implementations
        //Has the same complexity for Get and Put so won't make any difference
        //in terms of implementations
        HashMap hashTable = new HashMap();
        
        //Iterating through all combinations
        //6 missing ? so iterating through 16^4 combinations
        for(int a = 0; a < 16; a++){
            for(int b = 0; b < 16; b++){
                for(int c = 0; c < 16; c++){
                    for(int d = 0; d < 16; d++){
                        
                        //making different combinations of the string
                        String keyA = HEX[a] + HEX[b] + HEX[c] + HEX[d] + "1111111111";
                        
                        //putting in the parity bits
                        byte[] keyEncryptA = parityBitting(keyA);
                        
                        //converting into SecretKey
                        DESKeySpec keySpecEncryptA = new DESKeySpec(keyEncryptA);
                        SecretKeyFactory keyFactoryA = SecretKeyFactory.getInstance("DES");
                        SecretKey secretKeyA = keyFactoryA.generateSecret(keySpecEncryptA); 
                        
                        MeetInMiddle encrypting = new MeetInMiddle(secretKeyA, secretKeyA);
                        
                        String secretA = encrypting.encrypt(plainText).toLowerCase();
                        
                        hashTable.put(secretA, keyA);
                        //System.out.println(secretA);
                        //System.out.println("InsideA");
                        //end of the 4 for loops
                      
                    }
                }
            }
        }
        
        
        //Iterating through all combinations
        //6 missing ? so iterating through 16^6 combinations
        //the loops didn't break by just one 'break' so made a name tag 
        //similar to the post link: http://stackoverflow.com/questions/886955/breaking-out-of-nested-loops-in-java
        mainloop:
        for(int i = 0; i < 16; i++){
            for(int j = 0; j < 16; j++){
                for(int k = 0; k < 16; k++){
                    for (int l = 0; l < 16; l++){
                        for(int m = 0; m < 16; m++){
                            for(int n = 0; n < 16; n++){

                                String keyB = HEX[i] + HEX[j] + HEX[k] + HEX[l] + HEX[m] + HEX[n] + "22222222";

                                
                                //System.out.println(keyB);
                                byte[] keyEncryptB = parityBitting(keyB);

                                DESKeySpec keySpecEncryptB = new DESKeySpec(keyEncryptB);
                                SecretKeyFactory keyFactoryB = SecretKeyFactory.getInstance("DES");
                                SecretKey secretKeyB = keyFactoryB.generateSecret(keySpecEncryptB); 

                                //hashTable.put(cipher, secretKeyB);

                               MeetInMiddle decrypting = new MeetInMiddle(secretKeyB, secretKeyB);
                               String secretB = decrypting.decrypt(cipherText).toLowerCase();
                               
                               //following the psuedocode on piazza
                               //searching for the key if it exists in the hash table to find collision
                               
                               //Testing 
                               //System.out.println(hashTable.containsKey(secretB));
                               if(hashTable.containsKey(secretB) == true)
                               {
                                   //System.out.println("Hey I found something!");
                                   System.out.println("Found Key: " + hashTable.get(secretB) + keyB);
                                   break mainloop;
                               }
                                
                                //System.out.println(secretB);
                                //System.out.println("InsideB");
                                //end of the 6 for loops
                            }
                        }
                    }
                }
            }
        }
    
        
        //end of all for loops 
        
    }


    /**
     * @param args the command line arguments
     * @throws java.security.NoSuchAlgorithmException
     * @throws java.io.IOException
     * @throws java.io.UnsupportedEncodingException
     * @throws java.security.spec.InvalidKeySpecException
     * @throws java.security.InvalidKeyException
     * @throws javax.crypto.IllegalBlockSizeException
     * @throws javax.crypto.BadPaddingException
     */
    public static void main(String[] args) throws NoSuchAlgorithmException, IOException, UnsupportedEncodingException, InvalidKeySpecException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {        
        /*
        *****************************************************
        *               Meet in the Middle
        *****************************************************
        */
        
            
        String plainText = "48656c6c6f20576f726c6421";
        String cipherText = "e89d327477bd5da2f84bcc6d016617d2";
        
        //byte[] plain = DatatypeConverter.parseHexBinary(plainText);
        //byte[] cipher = DatatypeConverter.parseHexBinary(cipherText);
        
        MeetInMiddle attack = new MeetInMiddle();
        attack.MiM(plainText, cipherText);
        
        
    }
    
}
