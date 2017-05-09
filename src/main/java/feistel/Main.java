package feistel;/*
 * New BSD License (BSD)
 * Copyright (c) 2014,2015, Rob Shepherd
 *
 * All rights reserved.
 *
 * Parts derived from source code Copyright (c) 2012, Caio Yuri da Silva Costa
 *
 * Redistribution and use in source and binary forms, with or without modification, are permitted provided
 * that the following conditions are met:
 *
 *    Redistributions of source code must retain the above copyright notice, this list of conditions and the
 *    following disclaimer.
 *
 *    Redistributions in binary form must reproduce the above copyright notice, this list of conditions and
 *    the following disclaimer in the documentation and/or other materials provided with the distribution.
 *
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
 * PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR
 * ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED
 * TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

import cycle.CycleStruct;

import java.io.ByteArrayOutputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.util.*;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * Software derived from a New-BSD licensed implementation for .NET http://dotfpe.codeplex.com
 * ... That in turn was ported from the Botan library http://botan.randombit.net/fpe.html.
 * ... Using the scheme FE1 from the paper "Format-Preserving Encryption" by Bellare, Rogaway, et al. (http://eprint.iacr.org/2009/251)
 *
 * @author Rob Shepherd
 */
public class Main {
    public static void main(String[] args) throws Exception {
        final byte[] key = "Here is my secret key".getBytes();
        final byte[] tweak = "Here is my tweak".getBytes();


        //final int range = 999999;
        //final BigInteger modulus = new BigInteger("99999999");

        Set<BigInteger> results = new HashSet<BigInteger>();
        List<BigInteger> sequence = new ArrayList<>();
        long counter = 8;
        List<CycleStruct> cs = new ArrayList<>();
        cs.add(new CycleStruct(new BigInteger("10000000"), new BigInteger("99999999"), new BigInteger("10010000")));
        cs.add(new CycleStruct(new BigInteger("100000000"), new BigInteger("999999999"), new BigInteger("100010000")));
        cs.add(new CycleStruct(new BigInteger("1000000000"), new BigInteger("9999999999"), new BigInteger("1000010000")));
        cs.add(new CycleStruct(new BigInteger("10000000000"), new BigInteger("99999999999"), new BigInteger("10000010000")));
        cs.add(new CycleStruct(new BigInteger("100000000000"), new BigInteger("999999999999"), new BigInteger("100000010000")));
        cs.add(new CycleStruct(new BigInteger("1000000000000"), new BigInteger("9999999999999"), new BigInteger("1000000010000")));
        cs.add(new CycleStruct(new BigInteger("10000000000000"), new BigInteger("99999999999999"), new BigInteger("10000000010000")));
        cs.add(new CycleStruct(new BigInteger("100000000000000"), new BigInteger("999999999999999"), new BigInteger("100000000010000")));
        cs.add(new CycleStruct(new BigInteger("1000000000000000"), new BigInteger("9999999999999999"), new BigInteger("1000000000040000")));
        cs.add(new CycleStruct(new BigInteger("10000000"), new BigInteger("99999999"), new BigInteger("10010000")));
        for (CycleStruct c: cs) {
            long time = 0;
            while (true) {
                long startTime = System.nanoTime();
                BigInteger enc = encrypt(c.getMax(), c.getFirst(), key, tweak);
                long endTime = System.nanoTime();
                time += (endTime - startTime);
                BigInteger dec = decrypt(c.getMax(), enc, key, tweak);
                //System.out.println(i + ": " + enc + " " + dec);
                if (!Objects.equals(dec.toString(), c.getFirst().toString())) {
                    throw new IllegalStateException("enc (" + enc + ") != i(" + c.getFirst().toString() + ")");
                }
                results.add(enc);
                sequence.add(enc);
                //  if (enc.longValue() < 0 || enc.longValue() > range) {
                //    throw new IllegalStateException("enc " + enc + " out of range " + range);
                // }
                c.setFirst(c.getFirst().add(BigInteger.ONE));
                if (c.getFirst().toString().equals(c.getStop().toString())) {
                    break;
                }
            }
            double average = (double) time / 10000.;
            System.out.println(counter + " " + (average / 1000000));
            FileOutputStream stream = new FileOutputStream("f" + counter);
            PrintWriter writer = new PrintWriter(stream);
            for (BigInteger bigInteger : sequence) {
                String bits = "";
                for (int i = 0; i < bigInteger.bitLength(); i++) {
                  bits += bigInteger.testBit(i) ? 1 : 0;
                }
                writer.println(bits);
            }
            writer.close();
            counter++;
            if (counter == 16) {
                PrintWriter wr = new PrintWriter("ff16");
                for (BigInteger bigInteger : sequence) {
                    wr.println(bigInteger);
                }
                wr.close();
            }
            sequence = new ArrayList<>();
        }
    }

    // Normally FPE is for SSNs, CC#s, etc, nothing too big
    private static final int MAX_N_BYTES = 128 / 8;

    /// <summary>
    /// Generic Z_n FPE decryption, FD1 scheme
    /// </summary>
    /// <param name="modulus">Use to determine the range of the numbers. Example, if the
    /// numbers range from 0 to 999, use "1000" here.</param>
    /// <param name="ciphertext">The number to decrypt.</param>
    /// <param name="key">Secret key</param>
    /// <param name="tweak">Non-secret parameter, think of it as an IV - use the same one used to encrypt</param>
    /// <returns>The decrypted number</returns>
    private static BigInteger decrypt(BigInteger modulus, BigInteger ciphertext, byte[] key, byte[] tweak) throws Exception {
        FPE_Encryptor fpeEncryptor = new FPE_Encryptor(key, modulus, tweak);

        BigInteger[] a_b = NumberTheory.factor(modulus);

        BigInteger a = a_b[0];
        BigInteger b = a_b[1];

        int r = getRoundsNumber(a, b);

        BigInteger X = ciphertext;

        for (int i = 0; i < r; ++i) {
            BigInteger W = X.mod(a);
            BigInteger R = X.divide(a);

            BigInteger bigInteger = (W.subtract(fpeEncryptor.F(r - i - 1, R)));

            BigInteger L = bigInteger.mod(a);
            X = b.multiply(L).add(R);
        }

        return X;
    }

    /// <summary>
    /// Generic Z_n FPE encryption, FE1 scheme
    /// </summary>
    /// <param name="modulus">Use to determine the range of the numbers. Example, if the
    /// numbers range from 0 to 999, use "1000" here.</param>
    /// <param name="plaintext">The number to encrypt.</param>
    /// <param name="key">Secret key</param>
    /// <param name="tweak">Non-secret parameter, think of it as an IV</param>
    /// <returns>The encrypted number.</returns>
    public static BigInteger encrypt(BigInteger modulus, BigInteger plaintext,
                                     byte[] key,
                                     byte[] tweak) throws Exception {
        FPE_Encryptor fpeEncryptor = new FPE_Encryptor(key, modulus, tweak);

        BigInteger[] a_b = NumberTheory.factor(modulus);
        //System.out.println(a_b[0] + " " + a_b[1]);

        BigInteger a = a_b[0];
        BigInteger b = a_b[1];
        int r = getRoundsNumber(a, b);

        BigInteger X = plaintext;

        for (int i = 0; i != r; ++i) {
            BigInteger L = X.divide(b);
            BigInteger R = X.mod(b);

            BigInteger W = (L.add(fpeEncryptor.F(i, R))).mod(a);
            X = a.multiply(R).add(W);
        }

        return X;
    }

    /// <summary>
    /// According to a paper by Rogaway, Bellare, etc, the min safe number
    /// of rounds to use for FPE is 2+log_a(b). If a >= b then log_a(b) &lt;= 1
    /// so 3 rounds is safe. The FPE factorization routine should always
    /// return a >= b, so just confirm that and return 3.
    /// </summary>
    /// <param name="a"></param>
    /// <param name="b"></param>
    /// <returns></returns>
    private static int getRoundsNumber(BigInteger a, BigInteger b) throws Exception {
        if (a.compareTo(b) < 0)
            throw new Exception("FPE rounds: a < b");
        return 5;
    }

    /// <summary>
    /// A simple round function based on HMAC(SHA-256)
    /// </summary>
    private static class FPE_Encryptor {
        private Mac mac;

        private byte[] mac_n_t;

        public FPE_Encryptor(byte[] key, BigInteger modulus, byte[] tweak) throws Exception {
            mac = Mac.getInstance("HmacMD5");
            SecretKeySpec secret_key = new SecretKeySpec(key, "HmacMD5");
            mac.init(secret_key);

            byte[] modulusBinary = modulus.toByteArray();

            if (modulusBinary.length > MAX_N_BYTES)
                throw new Exception("N is too large for FPE encryption");

            ByteArrayOutputStream ms = new ByteArrayOutputStream();


            ms.write(modulusBinary.length);
            ms.write(modulusBinary);

            ms.write(tweak.length);
            ms.write(tweak);

            mac.reset();
            mac_n_t = mac.doFinal(ms.toByteArray());
        }

        BigInteger F(int round_no, BigInteger R) throws IOException {
            byte[] r_bin = R.toByteArray();
            ByteArrayOutputStream ms = new ByteArrayOutputStream();
            ms.write(mac_n_t);
            ms.write(round_no);
            ms.write(r_bin.length);
            ms.write(r_bin);
            mac.reset();
            byte[] X = mac.doFinal(ms.toByteArray());
            byte[] X_ = new byte[X.length + 1];
            X_[0] = 0; // set the first byte to 0

            System.arraycopy(X, 0, X_, 1, X.length);
            return new BigInteger(X_);
        }
    }


    private static class NumberTheory {
        private static final BigInteger MAX_PRIME = BigInteger.valueOf(65535);

        /// <summary>
        /// Factor n into a and b which are as close together as possible.
        /// Assumes n is composed mostly of small factors which is the case for
        /// typical uses of FPE (typically, n is a power of 10)
        ///
        /// Want a >= b since the safe number of rounds is 2+log_a(b); if a >= b
        /// then this is always 3
        /// </summary>
        /// <param name="n"></param>
        /// <param name="a"></param>
        /// <param name="b"></param>
        public static BigInteger[] factor(BigInteger n) throws Exception {
            BigInteger a = BigInteger.ONE;
            BigInteger b = BigInteger.ONE;

            int n_low_zero = low_zero_bits(n);
            if (n_low_zero > 0) {
                System.out.println("N zero bits " + n_low_zero);
            }

            a = a.shiftLeft(n_low_zero / 2);
            b = b.shiftLeft(n_low_zero - (n_low_zero / 2));

            n = n.shiftRight(n_low_zero);


            //for (int i = 0; i != PRIMES.length; ++i)
            BigInteger prime = BigInteger.ONE;
            while (prime.compareTo(MAX_PRIME) <= 0) {
                prime = prime.nextProbablePrime();
                while (n.mod(prime).compareTo(BigInteger.ZERO) == 0) {
                    a = a.multiply(prime);
                    if (a.compareTo(b) > 0) {
                        BigInteger old_b = b;
                        b = a;
                        a = old_b;
                    }
                    n = n.divide(prime);
                }
                if (a.compareTo(BigInteger.ONE) > 0 && b.compareTo(BigInteger.ONE) > 0) {
                    break;
                }
            }

            if (a.compareTo(b) > 0) {
                BigInteger old_b = b;
                b = a;
                a = old_b;
            }
            a = a.multiply(n);
            if (a.compareTo(b) < 0) {
                BigInteger old_b = b;
                b = a;
                a = old_b;
            }

            if (a.compareTo(BigInteger.ONE) < 0 || b.compareTo(BigInteger.ONE) < 0) {
                throw new Exception("Could not factor n for use in FPE");
            }

            // return
            return new BigInteger[]{a, b};
        }

        /// <summary>
        /// Counts the trailing zeroes of a byte
        /// </summary>
        /// <param name="n"></param>
        /// <returns></returns>
        private static int ctz(byte n) {
            for (int i = 0; i != 8; ++i) {
                if (((n >> i) & 0x01) > 0) {
                    return i;
                }
            }
            return 8;
        }

        /// <summary>
        /// Return the number of 0 bits at the end of n
        /// </summary>
        /// <param name="n"></param>
        /// <returns></returns>
        private static int low_zero_bits(BigInteger n) {
            int low_zero = 0;

            if (n.signum() > 0) {
                byte[] bytes = n.toByteArray();

                for (int i = bytes.length - 1; i >= 0; i--) {
                    int x = (bytes[i] & 0xFF);

                    if (x > 0) {
                        low_zero += ctz((byte) x);
                        break;
                    } else
                        low_zero += 8;
                }
            }

            return low_zero;
        }
    }
}