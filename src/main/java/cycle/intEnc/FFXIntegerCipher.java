package cycle.intEnc;

import cycle.Key;

import java.math.BigInteger;
import java.util.Arrays;
import java.util.BitSet;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import java.security.GeneralSecurityException;

public class FFXIntegerCipher extends IntegerCipher {

    private static final int MIN_BIT_LENGTH = 8;    //the minimum of ffx is 8 bit
    private static final int MAX_BIT_LENGTH = 128;    //ffx is restricted to 128 bit
    private static final byte VERS = 1;            //version: 1
    private static final byte METHOD = 2;        //ffx mode: 2 = alternating Feistel
    private static final byte ADDITION = 0;        //addition operator: characterwise addition (xor)
    private static final byte RADIX = 2;            //number of symbols in alphabet: {0, 1} = 2

    private FFXIntegerCipher(IntegerMessageSpace messageSpace) {
        super(messageSpace);
        if (messageSpace.getOrder().bitLength() > MAX_BIT_LENGTH)
            throw new IllegalArgumentException("Message space must not be bigger than 128 bit");
        if (messageSpace.getOrder().bitLength() < MIN_BIT_LENGTH)
            throw new IllegalArgumentException("Message space must be bigger or equal to 8 bit");
    }

    @Override
    public BigInteger encrypt(BigInteger plaintext, Key key, byte[] tweak) {
        return cipher(plaintext, key, tweak, true);
    }

    @Override
    public BigInteger decrypt(BigInteger ciphertext, Key key, byte[] tweak) {
        return cipher(ciphertext, key, tweak, false);
    }

    private BigInteger cipher(BigInteger input, Key key, byte[] tweak, boolean encryption) {
        BigInteger maxMsValue = getMessageSpace().getMaxValue();
        if (input == null || input.compareTo(BigInteger.ZERO) == -1
                || input.compareTo(maxMsValue) == 1 || key == null || tweak == null) {
            throw new IllegalArgumentException("Input value must not be null");
        }

        try {
            do {
                input = cipherFunction(input, key, tweak, encryption);
            }
            while (input.compareTo(maxMsValue) == 1);
        } catch (GeneralSecurityException e) {
            throw new IllegalArgumentException("A security exception occured: " + e.getMessage());
        }

        return input;
    }

    private BigInteger cipherFunction(BigInteger input, Key key, byte[] tweak, boolean encryption) throws GeneralSecurityException {
        int msBitLength = getMessageSpace().getOrder().bitLength();
        int middleIndex = (msBitLength + 1) / 2;
        int nrOfRounds = determineNrOfRounds(msBitLength);
        BitSet inputBitSet = bigIntegerToBitSet(input);
        BitSet b = inputBitSet.get(0, middleIndex);
        BitSet a = inputBitSet.get(middleIndex, msBitLength + 1);
        BitSet temp;

        IvParameterSpec ivspec = new IvParameterSpec(new byte[16]); //zero initialization vector is necessary, makes the AES encryption act as an AES CBC MAC
        Cipher aesCipher = Cipher.getInstance("AES/CBC/NoPadding");
        aesCipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key.getKey(32), "AES"), ivspec);

        byte[] p = new byte[]{0, VERS, METHOD, ADDITION, RADIX, (byte) msBitLength, (byte) middleIndex, (byte) nrOfRounds, 0, 0, 0, 0, 0, 0, 0, (byte) tweak.length}; //total 16 bytes
        p = aesCipher.doFinal(p);

        if (encryption) {
            for (int i = 0; i < nrOfRounds; i++) {
                a.xor(roundFunction(aesCipher, p, msBitLength, tweak, i, b, key.getKey(16)));
                temp = a;
                a = b;
                b = temp;
            }
        } else {
            for (int i = nrOfRounds - 1; i >= 0; i--) {
                temp = b;
                b = a;
                a = temp;
                a.xor(roundFunction(aesCipher, p, msBitLength, tweak, i, b, key.getKey(16)));
            }
        }
        BitSet returnBitSet = b.get(0, middleIndex);
        for (int j = middleIndex; j <= msBitLength; j++) {
            returnBitSet.set(j, a.get(j - middleIndex));
        }

        return bitSetToBigInteger(returnBitSet);
    }

    private BitSet roundFunction(Cipher aesCipher, byte[] p, int msBitLength, byte[] tweak, int roundNr, BitSet b, byte[] key) throws GeneralSecurityException {
        int middleIndex = (msBitLength + 1) / 2;

        byte[] paddedTweak = new byte[1 + tweak.length + ((((-tweak.length - 9) % 16) + 16) % 16)]; //  (%16)+16)%16 is necessary to prevent negative modulo values
        System.arraycopy(tweak, 0, paddedTweak, 0, tweak.length);
        paddedTweak[paddedTweak.length - 1] = (byte) roundNr;

//        byte[] paddedKKey = new byte[1 + key.length + ((((-key.length - 9) % 16) + 16) % 16)];
//        System.arraycopy(key, 0, paddedKKey, 0, key.length);
//        paddedKKey[paddedKKey.length - 1] = (byte) roundNr;
//        byte[] s = concatByteArrays(paddedKKey, new byte [] {60,93,-94,-128,
//                0,127,23,43,
//                -19,120,86,94,
//                -62,101,14,21});
//
//        paddedTweak = xorByteArray(paddedTweak, s);

        byte[] paddedB = new byte[8];
        System.arraycopy(b.toByteArray(), 0, paddedB, 0, b.toByteArray().length);

        byte[] q = concatByteArrays(paddedB, paddedTweak);


        byte[] encOutput = p;

        for (int m = 0; m < q.length; m += 16) {
            byte[] encInput = Arrays.copyOfRange(q, m, m + 16);
            encOutput = aesCipher.doFinal(xorByteArray(encInput, encOutput));
        }

        BitSet ciphertext = BitSet.valueOf(encOutput);

        if ((msBitLength % 2) == 0 || (roundNr % 2) != 0) {
            return ciphertext.get(128 - middleIndex, 128);
        } else {
            return ciphertext.get(128 - (middleIndex - 1), 128);
        }
    }


    private static BitSet bigIntegerToBitSet(BigInteger big) {
        BitSet bitSet = new BitSet(big.bitLength());
        for (int i = 0; i <= big.bitLength(); i++) {
            bitSet.set(i, big.testBit(i));
        }
        return bitSet;
    }

    private static BigInteger bitSetToBigInteger(BitSet bitset) {
        BigInteger big = BigInteger.ZERO;
        for (int i = 0; i < bitset.length(); i++) {
            if (bitset.get(i)) big = big.setBit(i);
        }
        return big;
    }

    private static byte[] concatByteArrays(byte firstBytes[], byte furtherBytes[]) {
        byte[] returnArray = new byte[firstBytes.length + furtherBytes.length];
        System.arraycopy(firstBytes, 0, returnArray, 0, firstBytes.length);
        System.arraycopy(furtherBytes, 0, returnArray, firstBytes.length, furtherBytes.length);
        return returnArray;
    }

    private static byte[] xorByteArray(byte[] array1, byte[] array2) {
        byte[] xorArray = new byte[array1.length];
        int i = 0;
        for (byte b : array1) {
            xorArray[i] = (byte) (b ^ array2[i++]);
        }
        return xorArray;
    }

    private static int determineNrOfRounds(int msBitLength) {
        if (msBitLength >= 32) {
            return 12;
        } else if (msBitLength >= 20) {
            return 18;
        } else if (msBitLength >= 14) {
            return 24;
        } else if (msBitLength >= 10) {
            return 30;
        } else if (msBitLength >= 8) {
            return 36;
        } else
            throw new RuntimeException("Bit length of message space has to be equal or greater than 8 bit.");
    }
}
