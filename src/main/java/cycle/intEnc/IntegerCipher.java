package cycle.intEnc;

import cycle.Key;

import java.math.BigInteger;

abstract class IntegerCipher {

	private IntegerMessageSpace messageSpace;

	IntegerCipher(IntegerMessageSpace messageSpace) {
		if (messageSpace == null) throw new IllegalArgumentException("Message space must not be null");
		this.messageSpace = messageSpace;
	}

	IntegerMessageSpace getMessageSpace() {
		return messageSpace;
	}

	public abstract BigInteger encrypt(BigInteger plaintext, Key key, byte[] tweak);

	public abstract BigInteger decrypt(BigInteger ciphertext, Key key, byte[] tweak);
}
