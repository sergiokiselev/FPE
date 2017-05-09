package prefix;

import sun.misc.BASE64Encoder;
import util.AES;

import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.*;

public class Prefix {

    public BigInteger encode(BigInteger number, List<InnerPrefix> prefices) {
        BigInteger result = new BigInteger("0");
        int e = 0;
        while (number.toString().compareTo("0") > 0) {
            BigInteger buf = number.mod(BigInteger.TEN);
            number = number.divide(BigInteger.TEN);
            int encoded = prefices.get(buf.intValue()).index;
            result = result.add(BigInteger.TEN.pow(e).multiply(new BigInteger("" + encoded)));
            e++;
        }
        return result;
    }
}