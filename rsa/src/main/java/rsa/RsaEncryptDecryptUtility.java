package rsa;


import java.security.KeyPair;


import java.security.PrivateKey;
import java.security.PublicKey;

import java.util.HashMap;
import java.util.Map;
import java.util.logging.Logger;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;


public class RsaEncryptDecryptUtility {
	
	public static String publicKeyFile = "Public.TXT";
	final static Logger log = Logger.getLogger(RsaEncryptDecryptUtility.class.getName());

	
	
	public static final void usage() {
	    System.out.println("Usage:");
	    System.out.println(" generatekey <n>: total number of shards for private key <k> : minumum shards for private key");
	    System.out.println(" encrypt <filename to encrypt>");
	    System.out.println(" decrypt <filename to decrypt> , <n> :total shards , <k> :minimum shards ");
	    System.exit(0);
	  }

	/*
	 * The generateKey  method generates Public key and private key .
	 * And store private key as shamir shard
	 * 
	 * @params Integer : total shards
	 * 
	 * @params Integer minimum shards 
	 * 
	 * @returns encryptedText a byte array representing the result of the
	 * encryption.
	 */  
	public static void generateKey(Integer total , Integer parts) {
		 RsakeyGenerator gcsr =  new RsakeyGenerator();
		 log.info("Generating Keypair");
		 KeyPair pair= gcsr.generateRSAkys(2048);
		 log.info("Generating Public and Private Keys");
		 gcsr.saveKeys(pair, total, parts);
		 System.out.println("\npublic key  and shard for private key saved successfully ");

	 }

	
	public static void encryptData(String dataFilename) throws Exception {
		
		RsakeyGenerator gcsr = new RsakeyGenerator();
		try {
			log.info("Reading Data file to be encrypted");
			final Path path = Paths.get(dataFilename);
			final byte[] data = Files.readAllBytes(path);

			// load public key from file
			final byte[] publicKeyBytes = RsaFileUtil.readFromFile(publicKeyFile);
			final PublicKey publicKey = gcsr.getPublicKey(publicKeyBytes);

			log.info("Encrypting Data");
			// encrypt
			byte[] encryptedData = gcsr.encrypt(data, publicKey);
			RsaFileUtil.writeFileHexFormat(dataFilename + ".encrypted", encryptedData);

		} catch (IOException io) {
			io.printStackTrace();
		} catch (Exception e) {
			e.printStackTrace();
		}

	}
	
	public static void decryptData(String fileName ,Integer total ,Integer part ) throws Exception {
		RsakeyGenerator gcsr = new RsakeyGenerator();
		try {
		// load encrypted data
	    final byte[] loadencryptedData = RsaFileUtil.readFromFile(fileName + ".encrypted");

	    // recreate Private Key using first two shards from files
	    final Map<Integer, byte[]> parts = new HashMap<>();
	    for (int i = 1; i <= part; i++) {
	      System.out.println("Value of i" + i); 	
	      final byte[] shard = RsaFileUtil.readFromFile("Shard[" + i + "].TXT");
	      parts.put(i, shard);
	    }

	    // use parts to regenerate private key
	    byte[] privateKeyBytes = ShamirUtil.shamirJoin(total, part, parts);
	    final PrivateKey privateKey = gcsr.getPrivateKey(privateKeyBytes);
	    
	 // use parts to regenerate private key
	    final byte[] decryptedData = gcsr.decrypt(loadencryptedData,privateKey);
	    RsaFileUtil.writeToFile(fileName + ".decryped", decryptedData);
		}catch(Exception e) {
			
		}
		
	}
	     
	  public static void main(String[] args) throws Exception {
		  try {
			  int length = args.length;
			  if (length <= 0) {
				  System.out.println("Please enter your choice : generateKey or encrypt or decrypt");
				  usage();
			  }
			  switch (args[0]) {
			  case "generatekey":
				  generateKey(Integer.parseInt(args[1]), Integer.parseInt(args[2]));
				  break;
			  case "encrypt":
				  encryptData(args[1]);
				  break;
			  case "decrypt":
				  decryptData(args[1], Integer.parseInt(args[2]), Integer.parseInt(args[3]));
				  break;
			  default:
				  usage();
			  }
			  System.out.println("Completed Successfully");
		  } catch (Exception e) {
			  e.printStackTrace();
			  usage();
		  }
	  
		 
		    
	        
	      
		    
		    
		  
		 
		   
	       
	        
	    
	       
                

	    }


}
