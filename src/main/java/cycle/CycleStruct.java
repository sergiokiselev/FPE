package cycle;

import java.math.BigInteger;

/**
 * User: NotePad.by
 * Date: 2/23/2017.
 */
public class CycleStruct {

    private BigInteger first;
    private BigInteger max;
    private BigInteger stop;

    public CycleStruct(BigInteger first, BigInteger max, BigInteger stop) {
        this.first = first;
        this.max = max;
        this.stop = stop;
    }

    public BigInteger getFirst() {
        return first;
    }

    public BigInteger getMax() {
        return max;
    }

    public BigInteger getStop() {
        return stop;
    }

    public void setFirst(BigInteger first) {
        this.first = first;
    }
}
