package token;

import util.AES;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import java.io.FileNotFoundException;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

/**
 * User: NotePad.by
 * Date: 4/2/2017.
 */
public class M3 {

    public static void main(String[] args) throws NoSuchAlgorithmException, InvalidKeyException, FileNotFoundException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException, NoSuchPaddingException {
        TokenGenerator generator = new TokenGenerator();
        PrintWriter writer = new PrintWriter("aes-token");
        SecretKey secretKey = AES.generateKey();
        byte[] parameterSpec = AES.generateIV(secretKey);
        BigInteger start = new BigInteger("1000000000000");
        BigInteger end = new BigInteger("1000000010000");
        while (!start.toString().equals(end.toString())) {
            BigInteger token = generator.generateAESToken(start, secretKey, new IvParameterSpec(parameterSpec));
            System.out.println(token);
            //System.out.println(token);
            String bits = "";
            for (int j = 0; j < token.bitLength(); j++) {
                bits += token.testBit(j) ? 1 : 0;
            }
            writer.println(bits);
            start = start.add(BigInteger.ONE);
        }
        writer.close();
    }

}
