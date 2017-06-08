package cycle;

import java.nio.ByteBuffer;
import java.nio.charset.Charset;
import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.KeySpec;
import java.util.HashMap;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

public class Key {

	private static final int PBKDF_ITERATION_COUNT = 10000;
	private static final byte[] PBKDF_SALT = new byte[]{39,3,-94,-128,0,127,13,43,-19,120,20,94,-62,101,14,91};
	
	private final HashMap<Integer,byte[]> keys = new HashMap<Integer,byte[]>(); //buffer keys for fast subsequent access
	private final int providedKeyLength; //length of the base key

	public Key(byte[] key) {
		if (key==null) throw new IllegalArgumentException("Key must not be null");
		providedKeyLength = key.length;
		keys.put(providedKeyLength, key);
	}
	public static boolean isKeyLengthAllowed(int keyLength) {
		try {
			return (keyLength<=Cipher.getMaxAllowedKeyLength("AES"));
		} catch (NoSuchAlgorithmException e) {
			throw new RuntimeException(e.getMessage());
		}
	}

	public byte[] getKey(int length) {
		if (!keys.containsKey(length)) deriveKey(length);
		return keys.get(length);
	}
	private void deriveKey(int length) {
		
		try {
			SecretKeyFactory kf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
			Charset charset = Charset.forName("UTF-8"); 
			char[] pw = charset.decode(ByteBuffer.wrap(keys.get(providedKeyLength))).array();         
		    KeySpec specs = new PBEKeySpec(pw, PBKDF_SALT, PBKDF_ITERATION_COUNT, length*8);
		    SecretKey key = kf.generateSecret(specs);
		    keys.put(length, key.getEncoded());
		} catch (GeneralSecurityException e) {
			throw new RuntimeException("Key derivation failed. " + e.getMessage()); 
		}
	}

}
