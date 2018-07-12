import java.io.BufferedOutputStream;
import java.io.BufferedReader;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.net.InetAddress;
import java.net.Socket;
import java.security.Key;
import java.util.Arrays;
import java.util.Random;
import java.security.*;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import com.sun.org.apache.xml.internal.security.utils.Base64;

import sun.security.provider.SecureRandom;

public class Lab5Client {
	
	public static String encryptedMessage;
	public static String key1 =null;
	public static SecretKey secretKey1;
	public static String decryptedMessage;
	
	public static String inputStreamOperation(Socket socket) {

		String message = null;
		try {

			BufferedReader brs = new BufferedReader(new InputStreamReader(socket.getInputStream()));
			// for test
			System.out.println("reading message");
			message = brs.readLine();
			// for test
			System.out.println(message + " <-received");
			//brs.reset();
			return message;
			
			

		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

		return null;
	}
	
	public static void outputStreamOperation(Socket socket, byte[] msg) { // changed msg from byte[]

		try {
			
			OutputStream out = socket.getOutputStream();			
			System.out.println("sending -> "+msg);
			out.write(msg);
			out.flush();
			
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}

	public static void main(String[] args) throws Exception{

        //Initialize socket
		Socket socket = new Socket("127.0.0.6", 4543);
		
        String msg = "kkkkkkkkkkkkkkkkk";
          
        encryptedMessage = encrypt(msg);
      
        String sendMsg = encryptedMessage + "%" + key1 + "\n";
        System.out.println("to server -> "+sendMsg);
        
        //to outpustream
        outputStreamOperation(socket, sendMsg.getBytes());
        System.out.println("------------------------");
        
        String[] encryptedMsgAndKey = inputStreamOperation(socket).split("%");
        System.out.println("received from server -> "+encryptedMsgAndKey);
        
        System.out.println("-------For decryption");
        SecretKey serverKey = decryptKey(encryptedMsgAndKey[1]);
        System.out.println("server key -> "+serverKey);
        decryptedMessage = decrypt(encryptedMsgAndKey[0], serverKey).toString();
        System.out.println("decrypted message from server -> "+decryptedMessage);
      
    }
	
	public static String encrypt(String message) throws Exception {
		
		try{
		
			
		key1 = "1234567812345678";
		byte[] digestOfPassword = key1.getBytes("utf-8");
        byte[] keyBytes = Arrays.copyOf(digestOfPassword, 24);
        for (int j = 0,  k = 16; j < 8;)
        {
            keyBytes[k++] = keyBytes[j++];
        }
		
        secretKey1 = new SecretKeySpec(keyBytes, "DESede");
        IvParameterSpec iv = new IvParameterSpec(new byte[8]);
        System.out.println("client key -> "+secretKey1);
        Cipher cipher = Cipher.getInstance("DESede/CBC/PKCS5Padding"); 
        cipher.init(Cipher.ENCRYPT_MODE, secretKey1, iv);

        byte[] plainTextBytes = message.getBytes("utf-8");
        byte[] cipherText = cipher.doFinal(plainTextBytes);        
        String encodedCipherText = new sun.misc.BASE64Encoder().encode(cipherText);       

        return encodedCipherText;    
		}
		catch (Exception e) {
			// TODO: handle exception
		}
         return null;
        
       }
	
	public static byte[] decrypt(String msg, SecretKey key11) throws Exception {
		try
        {
           
			
            IvParameterSpec iv = new IvParameterSpec(new byte[8]);
			
			
            Cipher decipher = Cipher.getInstance("DESede/CBC/PKCS5Padding"); 
            
            decipher.init(Cipher.DECRYPT_MODE, key11, iv);
            
            
            System.out.println("server key -> "+key11);
            System.out.println("to be decrypted -> "+msg);
            byte[] decodedMessage = new sun.misc.BASE64Decoder().decodeBuffer(msg);
            System.out.println("original encrypted message -> "+decodedMessage);
            byte[] plainText = decipher.doFinal(decodedMessage);          
           
            
            return plainText;            
        }
		catch (Exception e) {
			System.out.println(e);
		}
		return null;

	}
	
	public static SecretKey decryptKey(String key11) throws Exception {
		try
        {
           
			// to keep
            final byte[] digestOfPassword = key11.getBytes("utf-8");
            final byte[] keyBytes = Arrays.copyOf(digestOfPassword, 24);
            for (int j = 0,  k = 16; j < 8;)
            {
                keyBytes[k++] = keyBytes[j++];
            }

            SecretKey dSkey = new SecretKeySpec(keyBytes, "DESede");
            
            return dSkey;            
        }
		catch (Exception e) {
			System.out.println(e);
		}
		return null;

	}
	
}

