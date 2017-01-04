package prefix;

import sun.misc.BASE64Encoder;
import util.AES;

import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import java.nio.ByteBuffer;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.*;

public class Prefix {

    public Set<Integer> encrypt(List<Integer> numbers, SecretKey secretKey, IvParameterSpec ivParameterSpec) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, InvalidAlgorithmParameterException {
        List<InnerPrefix> prefices = new ArrayList<>();
        for (int i = 0; i < 10; i++) {
            byte[] sss = AES.encrypt(ByteBuffer.allocate(4).putInt(i).array(), secretKey, ivParameterSpec);
            InnerPrefix prefix = new InnerPrefix(new BASE64Encoder().encode(sss), i);
            prefices.add(prefix);
        }
        Collections.sort(prefices, new Comparator<InnerPrefix>() {
            @Override
            public int compare(InnerPrefix o1, InnerPrefix o2) {
                return o1.weight.compareTo(o2.weight);
            }
        });
        for (InnerPrefix prefix : prefices) {
            System.out.println(prefix.index + " " + prefix.weight);
        }
        Set<Integer> integers = new HashSet<>();
        for (int number : numbers) {
            int encoded = encode(number, prefices);
            System.out.println(encoded);
            integers.add(encoded);
        }
        return integers;
    }

    private static int encode(int number, List<InnerPrefix> prefices) {
        int result = 0;
        int e = 0;
        while (number > 0) {
            int buf = number % 10;
            number /= 10;
            int encoded = prefices.get(buf).index;
            result += Math.pow(10, e) * encoded;
            e++;
        }
        return result;
    }
}