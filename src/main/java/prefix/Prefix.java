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

import static prefix.TestPrefix.THOUSAND;

public class Prefix {

    public BigInteger encode(BigInteger number, List<InnerPrefix> prefices) {
        int offset = number.add(new BigInteger(THOUSAND.toByteArray()).negate()).intValue();
        return prefices.get(offset).getR();
    }
}