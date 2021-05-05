package rsa;

import java.io.FileOutputStream;
import java.io.IOException;

import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import java.util.Map;
import java.util.Map.Entry;
import java.security.Key;

public class RsakeyGenerator {

	private static PublicKey publickey = null;
	private final String ALGORITHM = "RSA";
	public static String publicKeyFile = "Public.TXT";

	/**
	 * Generates a new key pair
	 */
	public KeyPair generateRSAkys(int bits) {
		KeyPair kp = null;
		try {
			KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("RSA");
			keyPairGen.initialize(bits);
			kp = keyPairGen.generateKeyPair();
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
			System.out.print("No such algorithm RSA in constructor csrgenerator\n");
		}
		return kp;
	}

	/**
	 * Saves a public key to a file *
	 * 
	 * @param filename name of the file
	 * @param key      public key to be saved
	 * @return string representation of the pkcs8 object.
	 * @throws Exception
	 */
	public void SavePublicKey(String filename, KeyPair kp) throws Exception {
		// Writer out = null;
		FileOutputStream out = null;
		try {
			if (filename != null) {
				out = new FileOutputStream(filename + ".TXT");
			}
			System.err.println("Public key format: " + kp.getPublic().getFormat());
			publickey = kp.getPublic();
			X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(publickey.getEncoded());
			out.write(x509EncodedKeySpec.getEncoded());
			out.close();
		} catch (IOException io) {
			throw new Exception(io);
		}
	}

	/**
	 * reads a public key from a file
	 * 
	 * @param bytes     of the file
	 * @param algorithm is usually RSA
	 * @return the read public key
	 * @throws Exception
	 */
	public PublicKey getPublicKey(byte[] bytes) throws Exception {

		/* Generate public key. */
		X509EncodedKeySpec ks = new X509EncodedKeySpec(bytes);
		KeyFactory kf = KeyFactory.getInstance("RSA");
		PublicKey pub = kf.generatePublic(ks);
		return pub;
	}

	/**
	 * Saves a public key to a file and private keys as shamir shards
	 * 
	 * @param keypair
	 * @param total   part of shards
	 * @param minimum part of shard
	 * 
	 */
	public void saveKeys(KeyPair kp, int n, int k) {
		// write public key file
		RsaFileUtil.writeFileHexFormat(publicKeyFile, kp.getPublic().getEncoded());

		// write private key shard files
		final Map<Integer, byte[]> privateKeyParts = ShamirUtil.shamirSplit(n, k, kp.getPrivate().getEncoded());
		for (Entry<Integer, byte[]> entry : privateKeyParts.entrySet()) {
			RsaFileUtil.writeFileHexFormat("Shard[" + entry.getKey().intValue() + "].TXT", entry.getValue());
		}
	}

	/**
	 * Reads a Private Key from a file.
	 * 
	 * @param bytes     of the file
	 * @param algorithm Algorithm is usually "RSA"
	 * @return returns the privatekey which is read from the file;
	 * @throws Exception
	 */
	public PrivateKey getPrivateKey(byte[] bytes) throws Exception {

		/* Generate private key. */
		PKCS8EncodedKeySpec ks = new PKCS8EncodedKeySpec(bytes);
		KeyFactory kf = KeyFactory.getInstance("RSA");
		PrivateKey pvt = kf.generatePrivate(ks);
		return pvt;

	}
	/*
	 * The encrypt method takes in text and a key and encrypts the text using the
	 * RSA encryption algorithm.
	 * 
	 * @params text a String, the text to encrypt.
	 * 
	 * @params key a PublicKey to use in encryption.
	 * 
	 * @returns encryptedText a byte array representing the result of the
	 * encryption.
	 */

	public byte[] encrypt(byte[] text, PublicKey key) {
		byte[] encryptedText = null;
		Cipher cipher;
		try {
			cipher = Cipher.getInstance(ALGORITHM); // gets instance of RSA
			cipher.init(Cipher.ENCRYPT_MODE, key); // in encryption mode with the key
			encryptedText = cipher.doFinal(text); // carry out the encryption
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (NoSuchPaddingException e) {
			e.printStackTrace();
		} catch (IllegalBlockSizeException e) {
			e.printStackTrace();
		} catch (BadPaddingException e) {
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			e.printStackTrace();
		}
		return encryptedText; // return encrypted result
	}

	public byte[] decrypt(byte[] encryptedText, Key key) {
		byte[] decryptedText = null;
		Cipher cipher = null;
		try {
			cipher = Cipher.getInstance(ALGORITHM);
			/* Initializing the same cipher for decryption */
			cipher.init(Cipher.DECRYPT_MODE, key);

			// Decrypting the text
			decryptedText = cipher.doFinal(encryptedText);
			System.out.println(new String(decryptedText));
		} catch (InvalidKeyException e) {
			e.printStackTrace();
		} catch (IllegalBlockSizeException e) {
			e.printStackTrace();
		} catch (BadPaddingException e) {
			e.printStackTrace();
		} catch (NoSuchPaddingException e) {
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
		return decryptedText;
	}

}
