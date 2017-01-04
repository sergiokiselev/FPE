package prefix;

import util.AES;

import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;

/**
 * User: NotePad.by
 * Date: 1/4/2017.
 */
public class TestPrefix {

    public static void main(String[] args) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidAlgorithmParameterException {
        Prefix prefix = new Prefix();
        List<Integer> toEncode = new ArrayList<>();
        for (int i = 100000; i < 999999; i++) {
            toEncode.add(i);
        }
        SecretKey secretKey = AES.generateKey();
        byte[] iv = AES.generateIV(secretKey);
        IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);
        Set<Integer> result = prefix.encrypt(toEncode, secretKey, ivParameterSpec);
        System.out.println(result.size());
    }

}
