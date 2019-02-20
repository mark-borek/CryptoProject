   package cryptoFinalProj;
import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileInputStream;
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
import java.util.List; 

public class RSA_Test {
	
	private static final String PUBLIC_KEY_FILE = "public.key";
	private static final String PRIVATE_KEY_FILE = "private.key";

	public static void main(String[] args) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, IllegalBlockSizeException, BadPaddingException, ClassNotFoundException {
		
		
		System.out.println("------------------Generate Public and Private Key------------------");
		KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
		kpg.initialize(2048);
		KeyPair kp = kpg.generateKeyPair();
		Key pub = kp.getPublic();
		Key pvt = kp.getPrivate();
		KeyFactory factory = KeyFactory.getInstance("RSA");
		RSAPublicKeySpec pubKeySpec = factory.getKeySpec(pub,RSAPublicKeySpec.class);
		RSAPrivateKeySpec privKeySpec = factory.getKeySpec(pvt, RSAPrivateKeySpec.class);
		
		RSA rsaObj = new RSA(); 
		rsaObj.saveKeys(PUBLIC_KEY_FILE, pubKeySpec.getModulus(),pubKeySpec.getPublicExponent() );
		rsaObj.saveKeys(PRIVATE_KEY_FILE, privKeySpec.getModulus(),privKeySpec.getPrivateExponent() );
		System.out.println("-------------------------------------------------------------------");
		System.out.println("\n private key\n" + "modulus:" + privKeySpec.getModulus() + "\n" + "private exponent:" + privKeySpec.getPrivateExponent());
		
		System.out.println("-------------------------------------------------------------------");
		System.out.println("public key \n" + "modulus:" + pubKeySpec.getModulus() + "\n" + "private exponent:" + pubKeySpec.getPublicExponent());
		System.out.println("-------------------------------------------------------------------");

		String fileRead = rsaObj.readfile("text.txt");
		//encrypted data file in byte form 
		byte [] encryptedData = rsaObj.encryptData(fileRead.toString());
		System.out.println("--------------------------------------------------------------------");
		rsaObj.decryptData(encryptedData);
		
		
	}

	
	 
	 

}
