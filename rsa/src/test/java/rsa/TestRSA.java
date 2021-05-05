package rsa;



import static org.junit.Assert.*;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.HashMap;
import java.util.Map;
import java.util.logging.Logger;

import java.util.Base64;

import javax.crypto.Cipher;


import org.junit.Test;

public class TestRSA {

	private static final String STRING_TO_ENCRYPT = "hello";
	public static String publicKeyFile = "Public.TXT";
	public static String dataFilename = "data.TXT";
	public static Integer part =2;
	public static Integer total =5;
	private static final String CHAR_ENCODING = "UTF-8";
	
	RsakeyGenerator gcsr =  new RsakeyGenerator();
	final static Logger log = Logger.getLogger(TestRSA.class.getName());
	
	@Test
	public void testEncryptDecrypt() throws Throwable {

		RsakeyGenerator gcsr = new RsakeyGenerator();
		try {
			log.info("Reading Data file to be encrypted");
			final Path path = Paths.get(dataFilename);
			final byte[] data = Files.readAllBytes(path);

			// get the public key from file
			final byte[] publicKeyBytes = RsaFileUtil.readFromFile(publicKeyFile);
			final PublicKey publicKey = gcsr.getPublicKey(publicKeyBytes);

			// encrypt
			byte[] encryptedData = gcsr.encrypt(data, publicKey);
			RsaFileUtil.writeFileHexFormat(dataFilename + ".encrypted", encryptedData);

			final byte[] loadencryptedData = RsaFileUtil.readFromFile(dataFilename + ".encrypted");

		    /// create the private key using shard 2 & 3
		    final byte[] shard2 = RsaFileUtil.readFromFile("Shard[2].TXT");
		    final byte[] shard3 = RsaFileUtil.readFromFile("Shard[3].TXT");
		    final Map<Integer, byte[]> parts = new HashMap<>();
		    parts.put(2, shard2);
		    parts.put(3, shard3);

		    // use parts to generate private key
		    byte[] privateKeyBytes = ShamirUtil.shamirJoin(total, part, parts);
		    final PrivateKey recoveredPrivateKey = gcsr.getPrivateKey(privateKeyBytes);

		    final byte[] decryptedData = gcsr.decrypt(loadencryptedData,recoveredPrivateKey);
		    
		    final String decryptedString = new String(decryptedData, StandardCharsets.UTF_8);
		    System.out.println("Decrypyted String: " + decryptedString);
			
			assertEquals("decrypted stinrg is wrong!!",STRING_TO_ENCRYPT,decryptedString);
			
		} catch (Exception e1) {
			System.out.println("error: " + e1.getMessage());
		}

	}

	@Test
	public void generateKeys() throws Exception {
		 log.info("Generating Keypair");
		 KeyPair pair= gcsr.generateRSAkys(2048);
		 log.info("Generating Public and Private Keys");
		 gcsr.saveKeys(pair, 5, 2);
		System.out.println("Generated Keys  " );
		

	}

}
 
