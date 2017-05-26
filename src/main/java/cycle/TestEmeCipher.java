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
import java.util.*;

/**
 * User: NotePad.by
 * Date: 1/4/2017.
 */
public class TestEmeCipher {
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
//    private static byte[] keyArray = new byte[]{60,93,-94,-128,
//            0,127,23,43,
//            -19,120,86,94,
//            -62,101,14,21,
//            64,93,-94,-128,
//            0,127,23,43,
//            -19,120,86,94,
//            -62,101,15,29,
//            64,93,-94,-128,
//            0,127,23,43,
//            -19,120,86,94,
//            -62,101,14,30,
//            64,93,-94,-128,

    //            0,127,23,43,
//            -19,120,86,94,
//            -62,101,14,22};
    private static byte[] keyArray = new byte[]{60,93,-94,-128,
            0,127,23,43,
            -19,120,86,94,
            -62,101,14,21,
            0,127,23,43,
            64,93,-94,-128,
            64,93,-94,-128,
            -19,120,86,94,
            64,93,-94,-128,
            0,127,23,43,
            -19,120,86,94,
            -62,101,15,29,
            64,93,-94,-128,
            0,127,23,43,
            -19,120,86,94,
            -62,101,14,30,
            64,93,-94,-128,
            0,127,23,43,
            -19,120,86,94,
            -62,101,14,22};
    private static byte[] tweak = new byte[37];
    private static byte[] plaintext = new byte[43];
    private static byte[] msMax = new byte[500];
    private static IntegerMessageSpace intMS;

    public static void main(String[] args) throws FileNotFoundException {
        tweak[0] =  (byte)127;
        plaintext[0] = (byte)127;
        msMax[0] =  (byte)127;
        key = new Key(keyArray);
        BigInteger plaintext2 = BigInteger.valueOf(511);
        System.out.println(plaintext2);
        Set<BigInteger> res = new HashSet<>();
        long counter = 8;
        List<CycleStruct> cs = new ArrayList<>();
//        cs.add(new CycleStruct(new BigInteger("50000000"), new BigInteger("99999999"), new BigInteger("99999999")));
//        cs.add(new CycleStruct(new BigInteger("500000000"), new BigInteger("999999999"), new BigInteger("500010000")));
//        cs.add(new CycleStruct(new BigInteger("5000000000"), new BigInteger("9999999999"), new BigInteger("5000100000")));
//        cs.add(new CycleStruct(new BigInteger("50000000000"), new BigInteger("99999999999"), new BigInteger("50000010000")));
//        cs.add(new CycleStruct(new BigInteger("500000000000"), new BigInteger("999999999999"), new BigInteger("500000010000")));
//        cs.add(new CycleStruct(new BigInteger("5000000000000"), new BigInteger("9999999999999"), new BigInteger("5000000010000")));
//        cs.add(new CycleStruct(new BigInteger("50000000000000"), new BigInteger("99999999999999"), new BigInteger("50000000010000")));
        cs.add(new CycleStruct(new BigInteger("500000000000000"), new BigInteger("999999999999999"), new BigInteger("500000000010000")));
        Set<String> encryptedSet = new HashSet<>();
        //cs.add(new CycleStruct(new BigInteger("5000000000000000"), new BigInteger("9999999999999999"), new BigInteger("5000000001000000")));
        //cs.add(new CycleStruct(new BigInteger("500000000000000000000000"), new BigInteger("999999999999999999999999"), new BigInteger("500000000000000000010000")));
        for (CycleStruct c: cs) {
            //PrintWriter writer = new PrintWriter("ff_AES_256_CBC");
            PrintWriter writer = new PrintWriter("eme2_AES_ECB_256_15");
            intMS = new IntegerMessageSpace(c.getMax());
            //FFXIntegerCipher eme2 = new FFXIntegerCipher(intMS);
            EME2IntegerCipher eme2 = new EME2IntegerCipher(intMS);
            long times = 0;
//            BigInteger enc = eme2.encrypt(new BigInteger("5000000000000000"), key, tweak);
//            System.out.println(enc);
//            BigInteger dec = eme2.decrypt(enc, key, tweak);
//            System.out.println(dec);
            while (true) {
                long start = System.nanoTime();
                BigInteger encrypted = eme2.encrypt(c.getFirst(), key, tweak);
                encryptedSet.add(encrypted.toString());
                long duration = System.nanoTime() - start;
                times += duration;
                res.add(encrypted);
                String bits = "";
                for (int i = 0; i < encrypted.bitLength(); i++) {
                    bits += encrypted.testBit(i) ? 1 : 0;
                }
                writer.println(bits);
                c.setFirst(c.getFirst().add(BigInteger.ONE));
                if (c.getStop().toString().equals(c.getFirst().toString())) {
                    break;
                }
            }
            System.out.println("Encrypted set size: " + encryptedSet.size());
            int counter11 = 0;
            Iterator iterator = encryptedSet.iterator();
            while (counter11 < 1000) {
                counter11++;
                System.out.println(iterator.next());
            }
            double average = (double)times / 1000.;
            System.out.println(counter + " " + (average / 1000000));
            writer.close();
            counter++;
        }
    }
}
