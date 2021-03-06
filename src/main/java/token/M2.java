package token;

import java.io.FileNotFoundException;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

/**
 * User: NotePad.by
 * Date: 4/2/2017.
 */
public class M2 {

    public static void main(String[] args) throws NoSuchAlgorithmException, InvalidKeyException, FileNotFoundException {
        TokenGenerator generator = new TokenGenerator();
        PrintWriter writer = new PrintWriter("hash-token");
        for (int i = 0; i < 10000; i++) {
            BigInteger token = generator.generateHashToken(i);
            //System.out.println(token);
            String bits = "";
            for (int j = 0; j < token.bitLength(); j++) {
                bits += token.testBit(j) ? 1 : 0;
            }
            writer.println(bits);
        }
        writer.close();
    }

}
