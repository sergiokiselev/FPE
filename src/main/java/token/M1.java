package token;

import java.io.FileNotFoundException;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

/**
 * User: NotePad.by
 * Date: 4/2/2017.
 */
public class M1 {

    public static void main(String[] args) throws FileNotFoundException, InvalidKeyException, NoSuchAlgorithmException {
        TokenGenerator generator = new TokenGenerator();
        PrintWriter writer = new PrintWriter("random-token");
        for (int i = 0; i < 100000; i++) {
            BigInteger token = generator.generateRandomToken();
            String bits = "";
            for (int j = 0; j < token.bitLength(); j++) {
                bits += token.testBit(j) ? 1 : 0;
            }
            writer.println(bits);
        }
        writer.close();
    }



}
