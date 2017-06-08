package cycle.intEnc;

import cycle.Key;

import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.spec.SecretKeySpec;

public class EME2IntegerCipher extends IntegerCipher {

    private static final int KEY_SIZE = 16;

    public EME2IntegerCipher(IntegerMessageSpace messageSpace) {
        super(messageSpace);
    }

    @Override
    public BigInteger encrypt(BigInteger plaintext, Key key, byte[] tweak) {
        return cipher(plaintext, key, tweak, true);
    }

    @Override
    public BigInteger decrypt(BigInteger ciphertext, Key key, byte[] tweak) {
        return cipher(ciphertext, key, tweak, false);
    }

    private BigInteger cipher(BigInteger input, Key keyProvided, byte[] tweak, boolean encryption) {

        BigInteger maxMsValue = getMessageSpace().getMaxValue();
        if (input == null || input.compareTo(BigInteger.ZERO) < 0
                || input.compareTo(maxMsValue) > 0 || keyProvided == null || tweak == null) {
            throw new IllegalArgumentException("Input value must not be null.");
        }
        byte[] key;
        key = keyProvided.getKey(48);
        try {
            do {
                //System.out.println(input);
                input = cipherFunction(input, key, tweak, encryption);
            }
            while (input.compareTo(maxMsValue) > 0);
        } catch (GeneralSecurityException e) {
            throw new IllegalArgumentException("A security exception occured: " + e.getMessage());
        }
        return input;
    }


    private BigInteger cipherFunction(BigInteger input, byte[] key, byte[] tweak, boolean encryption) throws GeneralSecurityException {
        byte[] k1 = Arrays.copyOfRange(key, 0, KEY_SIZE);
        byte[] k2 = Arrays.copyOfRange(key, KEY_SIZE, 2 * KEY_SIZE);
        byte[] aesKey = Arrays.copyOfRange(key, 32, key.length);
        byte[] k3 = Arrays.copyOfRange(key, 2 * KEY_SIZE, 3 * KEY_SIZE);


        Cipher aesCipher = Cipher.getInstance("AES/ECB/NoPadding");
        aesCipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(aesKey, "AES"));
        byte[] tweakInBlockSize = new byte[KEY_SIZE];

        byte[] aesKeyInBlockSize = new byte[KEY_SIZE];
        List<byte[]> aesKeyArray = new ArrayList<>();
        List<byte[]> encAesKeyArray = new ArrayList<>();

        for (int m = 0; m < aesKey.length - 15; m += KEY_SIZE) {
            aesKeyArray.add(Arrays.copyOfRange(aesKey, m, m + KEY_SIZE));
        }
        if (aesKey.length % KEY_SIZE != 0) {
            aesKeyArray.add(Arrays.copyOfRange(aesKey, aesKey.length - (KEY_SIZE - ((-aesKey.length % KEY_SIZE) + KEY_SIZE) % KEY_SIZE), aesKey.length));
            aesKeyArray.set(aesKeyArray.size() - 1, padToBlocksize(aesKeyArray.get(aesKeyArray.size() - 1)));
        }
        k3 = multByAlpha(k3);

        for (byte[] a : aesKeyArray) {
            encAesKeyArray.add(xor(aesCipher.doFinal(xor(a, k3)), k3));
            k3 = multByAlpha(k3);
        }

        for (byte[] b : encAesKeyArray) {
            aesKeyInBlockSize = xor(aesKeyInBlockSize, b);
        }

        if (tweak.length == 0)
            tweakInBlockSize = aesCipher.doFinal(k2);
        else {
            List<byte[]> tweakArray = new ArrayList<>();
            List<byte[]> encTweakArray = new ArrayList<>();

            for (int m = 0; m < tweak.length - 15; m += KEY_SIZE) {
                tweakArray.add(Arrays.copyOfRange(tweak, m, m + KEY_SIZE));
            }
            if (tweak.length % KEY_SIZE != 0) {
                tweakArray.add(Arrays.copyOfRange(tweak, tweak.length - (KEY_SIZE - ((-tweak.length % KEY_SIZE) + KEY_SIZE) % KEY_SIZE), tweak.length));
                tweakArray.set(tweakArray.size() - 1, padToBlocksize(tweakArray.get(tweakArray.size() - 1)));
            }
            k2 = multByAlpha(k2);
            for (byte[] aTweakArray : tweakArray) {
                encTweakArray.add(xor(aesCipher.doFinal(xor(aTweakArray, k2)), k2));
                k2 = multByAlpha(k2);
            }
            for (byte[] encTweakBlock : encTweakArray) {
                tweakInBlockSize = xor(tweakInBlockSize, encTweakBlock);
            }
        }

        tweakInBlockSize = xor(tweakInBlockSize, aesKeyInBlockSize);

        if (!encryption) {
            aesCipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(aesKey, "AES"));
        }


        byte[] inputArray = input.toByteArray();
//        System.out.println("gegtrbtbtrbtr");
//        for (byte b: inputArray) {
//            System.out.print(b + " ");
//        }
//        System.out.println();

        if (inputArray[0] == 0) {
            inputArray = Arrays.copyOfRange(inputArray, 1, inputArray.length);
        }

        byte[] plaintext = new byte[getMessageSpace().getOrder().toByteArray().length];
        System.arraycopy(inputArray, 0, plaintext, plaintext.length - inputArray.length, inputArray.length);

        boolean lastPlainBlockIncomplete = false;
        if (plaintext.length % KEY_SIZE != 0) {
            lastPlainBlockIncomplete = true;
        }

        ArrayList<byte[]> plainArray = new ArrayList<>();
        byte[] copyOfKey2 = k1.clone();
        for (int m = 0; m < plaintext.length - 15; m += KEY_SIZE) {
            plainArray.add(Arrays.copyOfRange(plaintext, m, m + KEY_SIZE));
        }
        if (lastPlainBlockIncomplete)
            plainArray.add(Arrays.copyOfRange(plaintext, (plaintext.length - (KEY_SIZE - ((-plaintext.length % KEY_SIZE) + KEY_SIZE) % KEY_SIZE)), plaintext.length));

        int indexOfLastBlock = plainArray.size() - 1;


        ArrayList<byte[]> encPlainArray = new ArrayList<>();
        for (int i = 0; i < indexOfLastBlock; i++) {
            encPlainArray.add(aesCipher.doFinal(xor(k1, plainArray.get(i))));
            k1 = multByAlpha(k1);
        }
        if (lastPlainBlockIncomplete) {
            encPlainArray.add(padToBlocksize(plainArray.get(indexOfLastBlock)));
        } else {
            encPlainArray.add(aesCipher.doFinal(xor(k1, plainArray.get(indexOfLastBlock))));
        }
        byte[] mp, m, m1, mc, mc1, mm = null;
        byte[] mk, mkk = null;

        mp = tweakInBlockSize.clone();
        mk = aesKeyInBlockSize.clone();

        for (byte[] encPlainBlock : encPlainArray) {
            mp = xor(mp, encPlainBlock);
            mk = xor(mk, encPlainBlock);
        }
        mkk = aesCipher.doFinal(mk);
        if (lastPlainBlockIncomplete) {
            mm = aesCipher.doFinal(mp);
            mc = aesCipher.doFinal(mm);

            //  mkk = aesCipher.doFinal(mk);
            mc1 = mc.clone();
        } else {
            mc = aesCipher.doFinal(mp);
            //    mkk = aesCipher.doFinal(mk);
            mc1 = mc.clone();
        }
        m = xor(mp, mc);

        m1 = m.clone();

        ArrayList<byte[]> cipherArray = new ArrayList<byte[]>();
        cipherArray.add(new byte[KEY_SIZE]);

        for (int i = 1; i < indexOfLastBlock; i++) {
            if ((i - 1) % 128 > 0) {
                m = multByAlpha(m);
                cipherArray.add(xor(encPlainArray.get(i), m));
            } else {
                mp = xor(encPlainArray.get(i), m1);
                mc = aesCipher.doFinal(mp);
                m = xor(mp, mc);
                cipherArray.add(xor(mc, m1));
            }
        }
        byte[] lastCipherBlock = treatLastBlock(aesCipher, lastPlainBlockIncomplete, plainArray, indexOfLastBlock, encPlainArray, m, m1, mm, cipherArray);

//        System.out.println("kk");
//        for (byte[] a: cipherArray) {
//            for (byte b: a) {
//                System.out.print(b + " ");
//            }
//            System.out.println();
//        }
        // xor each encrypted block with the next one and set it as first element of the ciphertext array
        byte[] firstElementTemp = xor(mc1, tweakInBlockSize);
        //firstElementTemp = xor(firstElementTemp, mkk);
        //firstElementTemp = xor(firstElementTemp, aesKeyInBlockSize);
        for (byte[] cipherBlock : cipherArray) {
            firstElementTemp = xor(firstElementTemp, cipherBlock);
        }
        // if (encryption) {
        //firstElementTemp = xor(firstElementTemp, mkk);
        // }

        cipherArray.set(0, firstElementTemp);
//        System.out.println("ll");
//        for (byte[] a: cipherArray) {
//            for (byte b: a) {
//                System.out.print(b + " ");
//            }
//            System.out.println();
//        }
//        for (byte[] block : cipherArray) {
//            for (byte b: block) {
//                System.out.print(b + " ");
//            }
//            System.out.println();
//        }
        ArrayList<byte[]> encCipherArray = secondEncryption(aesCipher, lastPlainBlockIncomplete, indexOfLastBlock, copyOfKey2, cipherArray, lastCipherBlock);

        byte[] output = new byte[plaintext.length];
        int i = 0;
        for (byte[] encCipherBlock : encCipherArray) {
            for (byte byteValue : encCipherBlock) {
                output[i] = byteValue;
                i++;
            }
        }

        return new BigInteger(1, output); // returns a positive BigInteger
    }

    private ArrayList<byte[]> secondEncryption(Cipher aesCipher, boolean lastPlainBlockIncomplete, int indexOfLastBlock, byte[] copyOfKey2, ArrayList<byte[]> cipherArray, byte[] lastCipherBlock) throws IllegalBlockSizeException, BadPaddingException {
        byte[] key2;

        key2 = copyOfKey2.clone();
        ArrayList<byte[]> encCipherArray = new ArrayList<byte[]>();

        for (int i = 0; i < indexOfLastBlock; i++) {
            encCipherArray.add(xor(aesCipher.doFinal(cipherArray.get(i)), key2));
            key2 = multByAlpha(key2);
        }

        if (lastPlainBlockIncomplete) {
            encCipherArray.add(lastCipherBlock);
        } else {
            encCipherArray.add(xor(aesCipher.doFinal(cipherArray.get(indexOfLastBlock)), key2));
        }
        return encCipherArray;
    }

    private byte[] treatLastBlock(Cipher aesCipher, boolean lastPlainBlockIncomplete, ArrayList<byte[]> plainArray, int indexOfLastBlock, ArrayList<byte[]> encPlainArray, byte[] m, byte[] m1, byte[] mm, ArrayList<byte[]> cipherArray) throws IllegalBlockSizeException, BadPaddingException {
        byte[] lastCipherBlock = null;
        if (lastPlainBlockIncomplete) {
            byte[] truncatedMM = Arrays.copyOfRange(mm, 0, plainArray.get(indexOfLastBlock).length);
            lastCipherBlock = xor(plainArray.get(indexOfLastBlock), truncatedMM);
            cipherArray.add(padToBlocksize(lastCipherBlock));
        } else if ((indexOfLastBlock - 1) % 128 > 0) {
            m = multByAlpha(m);
            cipherArray.add(xor(encPlainArray.get(indexOfLastBlock), m));
        } else {
            cipherArray.add(xor(aesCipher.doFinal(xor(m1, encPlainArray.get(indexOfLastBlock))), m1));
        }
        return lastCipherBlock;
    }

    private static byte[] padToBlocksize(byte[] input) {
        if (input.length >= KEY_SIZE) return input;
        byte[] output = new byte[input.length + (((-input.length % KEY_SIZE) + KEY_SIZE) % KEY_SIZE)];
        System.arraycopy(input, 0, output, 0, input.length);
        output[input.length] = (byte) 128; //Set the first bit in the first padded block
        return output;
    }

    private static byte[] multByAlpha(byte[] input) {
//        System.out.println("Inn");
//        for (byte b: input) {
//            System.out.print(b + " ");
//        }
//        System.out.println();
//        System.out.println("Out");
        if (input.length != KEY_SIZE) throw new IllegalArgumentException("Input must be 16 bytes");
        byte[] output = new byte[KEY_SIZE];

        for (int i = 0; i < KEY_SIZE; i++) {
            output[i] = (byte) ((2 * input[i]) % 256);
            if (i > 0 && input[i - 1] > 127) {
                output[i] = (byte) (output[i] + 1);
            }
        }
//        for (byte b: output) {
//            System.out.print(b + " ");
//        }
//        System.out.println();
        return output;
    }

    private static byte[] xor(byte[] array1, byte[] array2) {
        if (array1.length != array2.length)
            throw new IllegalArgumentException("lenght of array1 (" + array1.length + ") must be equal to the length array2 (" + array2.length + ")");
        byte[] xorArray = new byte[array1.length];
        int i = 0;
        for (byte b : array1) {
            xorArray[i] = (byte) (b ^ array2[i++]);
        }
        return xorArray;
    }
}
