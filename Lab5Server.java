import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class Lab5Server {

	public static final String myAddress = "127/0/0/6";
	public static final String myPort = "4543";
	
	public static Cipher c;
	
	public static SecretKey secretKey;
	public static String key2;
	public static String key1;
	public static String encryptedMessage;
	public static String encryptedKey;
	public String decryptedMessage;
	public static SecretKey clientKey;
	
	
	public static String inputStreamOperation(Socket socket) {

		String message = null;
		try {

			BufferedReader brs = new BufferedReader(new InputStreamReader(socket.getInputStream()));
			System.out.println("reading message from Client");
			message = brs.readLine();
			
			System.out.println(message + " <-received");
			
			return message;
			
			

		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

		return null;
	}
	
	public static void outputStreamOperation(Socket socket, byte[] msg) { 

		try {
			
			OutputStream out = socket.getOutputStream();
			
			out.write(msg);;
			
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
	
	
	public static void main(String[] args) {
		// TODO Auto-generated method stub
		ConnectionModule();

	}
	
	public static void ConnectionModule()
	{
		try{
			
			String[] ipAddress = myAddress.split("/");
			int ip1 = Integer.parseUnsignedInt(ipAddress[0]);

			int ip2 = Integer.parseUnsignedInt(ipAddress[1]);
			int ip3 = Integer.parseUnsignedInt(ipAddress[2]);
			int ip4 = Integer.parseUnsignedInt(ipAddress[3]);

			byte[] ipAddr = new byte[] { (byte) ip1, (byte) ip2, (byte) ip3, (byte) ip4 };

		InetAddress addr = InetAddress.getByAddress(ipAddr);
		System.out.println(addr.getHostAddress());

		ServerSocket ss = new ServerSocket(Integer.parseInt(myPort), 0, addr);
		Socket s = ss.accept();
		// brs = new BufferedReader(new InputStreamReader(s.getInputStream()));
		String[] encryptedMsgAndKey = inputStreamOperation(s).split("%");
		
		System.out.println("From Client");
		System.out.println("---------------------------------");
		
		String msg1 = decrypt(encryptedMsgAndKey[0], encryptedMsgAndKey[1]).toString();
		System.out.println("decrypted message -> "+msg1);
		
		System.out.println("To Client");
		System.out.println("---------------------------------");
		encryptedMessage = encrypt(msg1);
		encryptedKey = encryptKey(secretKey);
		
		String sendMsg = encryptedMessage + "%" + key2 + "\n" ;
        System.out.println("send to Client -> "+sendMsg + "\n");
        
        //to outpustream
        outputStreamOperation(s, sendMsg.getBytes());
		
		}
		catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		
		
	}
	
	public static byte[] decrypt(String msg, String key11) throws Exception {
		try
        {
           
			// to keep
            final byte[] digestOfPassword = key11.getBytes("utf-8");
            final byte[] keyBytes = Arrays.copyOf(digestOfPassword, 24);
            for (int j = 0,  k = 16; j < 8;)
            {
                keyBytes[k++] = keyBytes[j++];
            }

            clientKey = new SecretKeySpec(keyBytes, "DESede");
            IvParameterSpec iv = new IvParameterSpec(new byte[8]);
			
			
			
            Cipher decipher = Cipher.getInstance("DESede/CBC/PKCS5Padding"); 
            
            decipher.init(Cipher.DECRYPT_MODE, clientKey, iv);
            
            System.out.println("to be decrypted -> "+msg);
            System.out.println("client key -> "+clientKey);
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
	
	public static String encrypt(String message) throws Exception {
		
		try{
		
		key2 = "1234567822345678";
		byte[] digestOfPassword = key2.getBytes("utf-8");
        //System.out.println(digestOfPassword.toString());
        byte[] keyBytes = Arrays.copyOf(digestOfPassword, 24);
        for (int j = 0,  k = 16; j < 8;)
        {
            keyBytes[k++] = keyBytes[j++];
        }
		
        secretKey = new SecretKeySpec(keyBytes, "DESede");
        IvParameterSpec iv = new IvParameterSpec(new byte[8]);
        System.out.println("server key ->"+secretKey);
        Cipher cipher = Cipher.getInstance("DESede/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, iv);
        
        byte[] plainTextBytes = message.getBytes("utf-8");
        byte[] cipherText = cipher.doFinal(plainTextBytes);
        System.out.println("message byte encrypted -> "+cipherText);
        String encodedCipherText = new sun.misc.BASE64Encoder().encode(cipherText);
        

        return encodedCipherText;    
		}
		catch (Exception e) {
			// TODO: handle exception
		}
         return null;
        
       }
	
	public static String encryptKey(SecretKey message) throws Exception {
		
		try{
		
		
        IvParameterSpec iv = new IvParameterSpec(new byte[8]);
        System.out.println("key ->"+clientKey.toString());
        Cipher cipher = Cipher.getInstance("DESede/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, clientKey, iv);
        
        byte[] plainTextBytes = message.getEncoded();
        byte[] cipherText = cipher.doFinal(plainTextBytes);
        System.out.println("byte key encrypted -> "+cipherText);
        String encodedCipherKey = new sun.misc.BASE64Encoder().encode(cipherText);
        System.out.println("encoded msg ->"+encodedCipherKey.length());

        return encodedCipherKey;    
		}
		catch (Exception e) {
			// TODO: handle exception
		}
         return null;
        
       }

}
