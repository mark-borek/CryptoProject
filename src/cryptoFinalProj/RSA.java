package cryptoFinalProj;

/**
 * Mark Borek 
 * 05/08/18
 * Cryptography Project that takes a text file and encrypts it then decrypts it. 
 */
import java.io.BufferedOutputStream;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException; 
import javax.crypto.NoSuchPaddingException;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.ArrayList;
import java.util.List;

public class RSA {
	
	private static final String PUBLIC_KEY_FILE = "public.key";
	private static final String PRIVATE_KEY_FILE = "private.key";	
	
	public RSA()
	{
		
	}
		/**
		 * method to save the public and private keys 
		 * @param fileName string 
		 * @param mod BigInteger 
		 * @param exp BigInteger
		 * @throws IOException
		 */
		protected void saveKeys(String fileName, BigInteger mod, BigInteger exp) throws IOException 
		{
			FileOutputStream fos = null;
			ObjectOutputStream oos = null; 
			try {
				System.out.println("Generating " + fileName + "...");
				fos = new FileOutputStream(fileName);
				oos = new ObjectOutputStream(new BufferedOutputStream(fos));
				oos.writeObject(mod);
				oos.writeObject(exp);
				System.out.println(fileName + " generated successfully");
			   }
			catch (Exception e) 
			{
				e.printStackTrace();
			}
			finally 
			{
				if(oos != null)
				{
					oos.close();
					if (fos != null)
						fos.close();
				}
			}
					
		}
		/**
		 * encrypts the data, passed as a string, into a single byte using the public key that was previously generated 
		 * @param data String of data being encrypted 
		 * @return byte[] data in byte format 
		 * @throws IOException
		 * @throws IllegalBlockSizeException
		 * @throws BadPaddingException
		 * @throws ClassNotFoundException
		 * @throws InvalidKeySpecException
		 */
		 protected byte [] encryptData(String data) throws IOException, IllegalBlockSizeException, BadPaddingException, ClassNotFoundException, InvalidKeySpecException
		 {
			 System.out.println("Data before encryption: " + data);
			 byte [] dataToEncrypt = data.getBytes();
			 byte [] encryptedData = null; 
			 try 
			 {
				 PublicKey pubKey = readPublicKeyFromFile(PUBLIC_KEY_FILE);
				 System.out.println("Public key: " + pubKey);
				 Cipher cipher = Cipher.getInstance("RSA");
				 cipher.init(Cipher.ENCRYPT_MODE, pubKey);
				 encryptedData = cipher.doFinal(dataToEncrypt);
				 System.out.println("Encrypted Data: " + encryptedData);
			 }
			 catch (IOException | NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException |  IllegalBlockSizeException | BadPaddingException | ClassNotFoundException | InvalidKeySpecException e )
			 {
				 e.printStackTrace();
			 }
			 return encryptedData; 
		 }
		 /**
		  * decrypts the data param using the privateKey
		  * @param data byte[] encrypt data member  
		  * @throws IOException 
		  * @throws ClassNotFoundException
		  * @throws InvalidKeySpecException
		  */
		 protected void decryptData(byte [] data) throws IOException, ClassNotFoundException, InvalidKeySpecException
		 {
			 byte[] descryptedData = null; 
			 try
			 {
				 PrivateKey privateKey = readPrivateKeyFromFile(this.PRIVATE_KEY_FILE);
				 Cipher cipher = Cipher.getInstance("RSA");
				 cipher.init(Cipher.DECRYPT_MODE, privateKey);
				 descryptedData = cipher.doFinal(data);
				 System.out.println("Decrypted Data: " + new String(descryptedData));
			 }
			 catch (IOException | NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException e)
			 {
				 e.printStackTrace();
			 }
		 }
		 /**
		  * reads the public key from the save key file 
		  * @param fileName String name of the file
		  * @return PublicKey object from the save key file 
		  * @throws IOException
		  * @throws ClassNotFoundException
		  * @throws InvalidKeySpecException
		  */
		 public PublicKey readPublicKeyFromFile(String fileName) throws IOException, ClassNotFoundException, InvalidKeySpecException 
		 {
			 FileInputStream fis = null; 
			 ObjectInputStream ois = null; 
			 try
			 {
				 fis = new FileInputStream(new File(fileName));
				 ois = new ObjectInputStream(fis); 
				 BigInteger modulus = (BigInteger) ois.readObject();
				 BigInteger exponent = (BigInteger) ois.readObject();
				 //Get Public Key 
				 
				 RSAPublicKeySpec rsaPublicKeySpec = new RSAPublicKeySpec(modulus,exponent);
				 KeyFactory fact = KeyFactory.getInstance("RSA");
				 PublicKey publicKey = fact.generatePublic(rsaPublicKeySpec);
				 //System.out.println(publicKey);
				 return publicKey;
			 }
			 catch (IOException | NoSuchAlgorithmException | ClassNotFoundException | InvalidKeySpecException  e )
			 {
				 e.printStackTrace();
			 }
			 finally
			 {
				 if (ois != null)
				 {
					 ois.close();
					 if(fis != null)
						 fis.close();
				 }
			 }
			return null;
		 }
		 /**
		  * this reads the private key from the save file and is used in the decrypt function 
		  * @param fileName name of the of file 
		  * @return PrivateKey object from the save key file 
		  * @throws IOException
		  * @throws ClassNotFoundException
		  * @throws InvalidKeySpecException
		  */
		 public PrivateKey readPrivateKeyFromFile(String fileName) throws IOException, ClassNotFoundException, InvalidKeySpecException
		 {
			 FileInputStream fis = null; 
			 ObjectInputStream ois = null; 
			 try
			 {
				 fis = new FileInputStream(new File(fileName));
				 ois = new ObjectInputStream(fis); 
				 BigInteger modulus = (BigInteger) ois.readObject();
				 BigInteger exponent = (BigInteger) ois.readObject();
				 
				 RSAPrivateKeySpec rsaPrivateKeySpec = new RSAPrivateKeySpec(modulus, exponent);
				 KeyFactory fact = KeyFactory.getInstance("RSA");
				 PrivateKey privateKey = fact.generatePrivate(rsaPrivateKeySpec);
				 return privateKey;
			 }
			 catch (IOException | NoSuchAlgorithmException | ClassNotFoundException | InvalidKeySpecException e )
			 {
				e.printStackTrace();
			 }
			 finally
			 {
				 if (ois != null)
				 {
					 ois.close();
					 if(fis != null)
						 fis.close();
				 }
			 }
			return null;
		 }
		 /**
		  * file that reads a file and outputs it as a string (used for text file)
		  * @param fileName String for name of the file 
		  * @return String for the file 
		  * @throws IOException
		  */
		 public String readfile(String fileName) throws IOException
		 {
			
			 BufferedReader br = new BufferedReader(new FileReader(fileName));
			 try {
			     StringBuilder sb = new StringBuilder();
			     String line = br.readLine();

			     while (line != null) {
			         sb.append(line);
			         sb.append(System.lineSeparator());
			         line = br.readLine();
			     }
			     String everything = sb.toString();
			     return everything; 
			 } finally {
			     br.close();
			 }
		 }
		 
	    
}
