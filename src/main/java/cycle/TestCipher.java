package cycle;

import cycle.intEnc.FFXIntegerCipher;
import cycle.messageSpace.IntegerMessageSpace;
import sun.misc.BASE64Encoder;
import util.AES;

import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.BitSet;
import java.util.HashSet;
import java.util.Set;

/**
 * User: NotePad.by
 * Date: 1/4/2017.
 */
public class TestCipher {
    public static void main(String[] args) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, InvalidAlgorithmParameterException {
        BigInteger aaa = new BigInteger("2131231");
        BitSet set = new BitSet(aaa.bitLength());
        for (int i = 0; i < aaa.bitLength(); i++) {
            set.set(i, aaa.testBit(i));
            System.out.println(set.get(i));
        }

        SecretKey secretKey = AES.generateKey();
        byte[] iv = AES.generateIV(secretKey);
        IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);
        BASE64Encoder encoder = new BASE64Encoder();
        byte[] encrypted = AES.encrypt(set.toByteArray(), secretKey, ivParameterSpec);
        BitSet set1 = BitSet.valueOf(encrypted);
        long[] aaaa = set1.toLongArray();
        System.out.println(new BigInteger(set1.toByteArray()));
        for (int i = 0; i < 100; i++) {
            encrypted = encoder.encode(AES.encrypt(set1.toByteArray(), secretKey, ivParameterSpec)).getBytes();
            System.out.println(encrypted.length);
            set1 = BitSet.valueOf(encrypted);
            System.out.println(new BigInteger(set1.toByteArray()));
        }

        System.out.println(BitSet.valueOf(encrypted));
    }
}
