package prefix;

import cycle.CycleStruct;
import sun.misc.BASE64Encoder;
import util.AES;

import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import java.io.FileNotFoundException;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.*;

/**
 * User: NotePad.by
 * Date: 1/4/2017.
 */
public class TestPrefix {

    static BigInteger THOUSAND = new BigInteger("1000");

    public static void main(String[] args) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidAlgorithmParameterException, FileNotFoundException {
        Prefix prefix = new Prefix();
        SecretKey secretKey = AES.generateKey();
        byte[] iv = AES.generateIV(secretKey);
        //IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);
        List<CycleStruct> cs = new ArrayList<>();
        cs.add(new CycleStruct(new BigInteger(THOUSAND.toByteArray()), new BigInteger("9999"), new BigInteger("9999")));
//        cs.add(new CycleStruct(new BigInteger("100000000"), new BigInteger("999999999"), new BigInteger("100100000")));
//        cs.add(new CycleStruct(new BigInteger("1000000000"), new BigInteger("9999999999"), new BigInteger("1000100000")));
//        cs.add(new CycleStruct(new BigInteger("10000000000"), new BigInteger("99999999999"), new BigInteger("10000100000")));
//        cs.add(new CycleStruct(new BigInteger("100000000000"), new BigInteger("999999999999"), new BigInteger("100000100000")));
//        cs.add(new CycleStruct(new BigInteger("1000000000000"), new BigInteger("9999999999999"), new BigInteger("1000000100000")));
//        cs.add(new CycleStruct(new BigInteger("10000000000000"), new BigInteger("99999999999999"), new BigInteger("10000000100000")));
//        cs.add(new CycleStruct(new BigInteger("100000000000000"), new BigInteger("999999999999999"), new BigInteger("100000000100000")));
//        cs.add(new CycleStruct(new BigInteger("1000000000000000"), new BigInteger("9999999999999999"), new BigInteger("1000000000100000")));
        int counter = 8;
        List<InnerPrefix> prefixes = initCipher(secretKey, null, new CycleStruct(new BigInteger(THOUSAND.toByteArray()), new BigInteger("9999"), null));
        for (CycleStruct c: cs) {
            long time = 0;
            List<BigInteger> result = new ArrayList<>();
            while (true) {
                long startTime = System.nanoTime();
                BigInteger enc = prefix.encode(c.getFirst(), prefixes);
                long endTime = System.nanoTime();
                time += (endTime - startTime);
                result.add(enc);
                c.setFirst(c.getFirst().add(BigInteger.ONE));
                if (c.getFirst().equals(c.getStop())) {
                    break;
                }
            }
            System.out.println(counter + " " + ((double) time / 100000.));
            //System.out.println(result.size());
            PrintWriter writer = new PrintWriter("p" + counter + "_" + 256 + "_ECB");
            for (BigInteger bigInteger : result) {
                //System.out.println(bigInteger);
                String bits = "";
                for (int i = 0; i < bigInteger.bitLength(); i++) {
                    bits += bigInteger.testBit(i) ? 1 : 0;
                }
                writer.println(bits);
            }
            writer.close();
            counter++;
        }
    }

    private static List<InnerPrefix> initCipher(SecretKey secretKey, IvParameterSpec ivParameterSpec, CycleStruct cs)
            throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, InvalidKeyException, NoSuchPaddingException {
        List<InnerPrefix> prefices = new ArrayList<>();
        while (true) {
            BigInteger a = cs.getFirst();
            if (a.toString().equals(cs.getMax().toString())) {
                break;
            }
            byte[] b = AES.encrypt(a.toByteArray(), secretKey, ivParameterSpec);
            InnerPrefix prefix = new InnerPrefix(new BASE64Encoder().encode(b), a);
            prefices.add(prefix);
            cs.setFirst(cs.getFirst().add(BigInteger.ONE));
        }
        Collections.sort(prefices, new Comparator<InnerPrefix>() {
            @Override
            public int compare(InnerPrefix o1, InnerPrefix o2) {
                return o1.weight.compareTo(o2.weight);
            }
        });
        BigInteger counter = new BigInteger(THOUSAND.toByteArray());
        for (InnerPrefix innerPrefix: prefices) {
            innerPrefix.setR(counter);
            counter = counter.add(BigInteger.ONE);
        }
        Collections.sort(prefices, new Comparator<InnerPrefix>() {
            @Override
            public int compare(InnerPrefix o1, InnerPrefix o2) {
                return o1.index.compareTo(o2.index);
            }
        });
//        for (InnerPrefix prefix : prefices) {
//            System.out.println(prefix.index + " " + prefix.getR());
//        }
        return prefices;
    }
}



// Сравнить быстродействие. 2 вида процессоров, разная загрузка
// Зависимость быстродействия от длины числа 6 - 16

// NIST RAND