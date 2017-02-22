package cycle;

import cycle.intEnc.EME2IntegerCipher;
import cycle.intEnc.FFXIntegerCipher;
import cycle.intEnc.IntegerCipher;
import cycle.messageSpace.IntegerMessageSpace;
import sun.misc.BASE64Encoder;
import util.AES;

import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import java.io.FileNotFoundException;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.BitSet;
import java.util.HashSet;
import java.util.Objects;
import java.util.Set;

/**
 * User: NotePad.by
 * Date: 1/4/2017.
 */
public class TestCipher {
//    public static void main(String[] args) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, InvalidAlgorithmParameterException {
//        BigInteger aaa = new BigInteger("2131231");
//        BitSet set = new BitSet(aaa.bitLength());
//        for (int i = 0; i < aaa.bitLength(); i++) {
//            set.set(i, aaa.testBit(i));
//            System.out.println(set.get(i));
//        }
//
//        SecretKey secretKey = AES.generateKey();
//        byte[] iv = AES.generateIV(secretKey);
//        IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);
//        BASE64Encoder encoder = new BASE64Encoder();
//        byte[] encrypted = AES.encrypt(set.toByteArray(), secretKey, ivParameterSpec);
//        BitSet set1 = BitSet.valueOf(encrypted);
//        long[] aaaa = set1.toLongArray();
//        System.out.println(new BigInteger(set1.toByteArray()));
//        for (int i = 0; i < 100; i++) {
//            encrypted = encoder.encode(AES.encrypt(set1.toByteArray(), secretKey, ivParameterSpec)).getBytes();
//            System.out.println(encrypted.length);
//            set1 = BitSet.valueOf(encrypted);
//            System.out.println(new BigInteger(set1.toByteArray()));
//        }
//
//        System.out.println(BitSet.valueOf(encrypted));
//    }
    private static  Key key;
    private static byte[] keyArray = new byte[]{60,93,-94,-128,0,127,23,43,-19,120,86,94,-62,101,14,21,64,93,-94,-128,0,127,23,43,-19,120,86,94,-62,101,15,29,64,93,-94,-128,0,127,23,43,-19,120,86,94,-62,101,14,30,64,93,-94,-128,0,127,23,43,-19,120,86,94,-62,101,14,22};
    private static byte[] tweak = new byte[37];
    private static byte[] plaintext = new byte[43];
    private static byte[] msMax = new byte[500];
    private static IntegerMessageSpace intMS;

    public static void main(String[] args) throws FileNotFoundException {
        tweak[0] =  (byte)127;
        plaintext[0] = (byte)127;
        msMax[0] =  (byte)127;
        key = new Key(keyArray);
        BigInteger maxValue = new BigInteger("999999999");
        System.out.println(maxValue);
        //intMS = new IntegerMessageSpace(maxValue);
        intMS = new IntegerMessageSpace(new BigInteger("999999999"));
        EME2IntegerCipher eme2 = new EME2IntegerCipher(intMS);
        BigInteger plaintext2 = BigInteger.valueOf(511);
        BigInteger ciphertext = eme2.encrypt(plaintext2, key,tweak);
        BigInteger decPlaintext = eme2.decrypt(ciphertext, key,tweak);
        System.out.println(plaintext2);
        System.out.println(decPlaintext);
        Set<BigInteger> res = new HashSet<>();
        long counter = 0;
        BigInteger first = new BigInteger("100000000");
        PrintWriter writer = new PrintWriter("outEME2");
        while (true) {
            BigInteger encrypted = eme2.encrypt(first, key, tweak);
            res.add(encrypted);
            String bits = "";
            for (int i = 0; i < encrypted.bitLength(); i++) {
              bits += encrypted.testBit(i) ? 1 : 0;
             }
            writer.println(bits);
            first = first.add(BigInteger.ONE);
            counter++;
            if (counter % 1000 == 0)
            System.out.println(encrypted);
            if ("100100000".equals(first.toString())) {
                break;
            }
        }
        writer.close();
        System.out.println(res.size());
    }
}
