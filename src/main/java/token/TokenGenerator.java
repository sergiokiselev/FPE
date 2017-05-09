package token;

import util.AES;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Random;

/**
 * User: NotePad.by
 * Date: 4/2/2017.
 */
public class TokenGenerator {

    private static SecureRandom random = new SecureRandom();
    private Mac mac;

    TokenGenerator() throws NoSuchAlgorithmException, InvalidKeyException {
        final byte[] key = "Here is my secret key".getBytes();
        mac = Mac.getInstance("HmacMD5");
        SecretKeySpec secret_key = new SecretKeySpec(key, "HmacMD5");
        mac.init(secret_key);
    }

    synchronized BigInteger generateRandomToken() {
        return new BigInteger(64, random);
    }

    synchronized BigInteger generateHashToken(int id) {
        mac.reset();
        byte[] result = mac.doFinal(ByteBuffer.allocate(4).putInt(id).array());
        return new BigInteger(result);
    }

    private static byte[] keyArray = new byte[]{60,93,-94,-128,
            0,127,23,43,
            -19,120,86,94,
            -62,101,14,21};

    synchronized BigInteger generateAESToken(BigInteger id, SecretKey key, IvParameterSpec parameterSpec) throws NoSuchPaddingException, NoSuchAlgorithmException, BadPaddingException, IllegalBlockSizeException, InvalidAlgorithmParameterException, InvalidKeyException {
        // Initialize AES
        AES aes = new AES();
        byte[] kk = aes.encrypt(id.toByteArray(), key, parameterSpec);
        System.out.println(kk);
        return new BigInteger(kk);
    }

}
