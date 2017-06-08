package cycle.intEnc;

import java.math.BigInteger;

public class IntegerMessageSpace {

	private final BigInteger min;
	private final BigInteger max;

	public IntegerMessageSpace(BigInteger max) {
		this.min = BigInteger.ZERO;
		this.max = max;
		if ((min == null) || (max == null))
			throw new IllegalArgumentException("Min and max must not be null.");
		if (min.compareTo(max) > 0)
			throw new IllegalArgumentException("Min can't be greater than max.");
	}

	public BigInteger getOrder() {
		return max.subtract(min).add(BigInteger.ONE);
	}

	public BigInteger getMaxValue() {
		return max;
	}
}
