package prefix;

import java.math.BigInteger;

class InnerPrefix {
    String weight;
    BigInteger index;
    private BigInteger r;

    InnerPrefix(String weight, BigInteger index) {
        this.weight = weight;
        this.index = index;
    }

    public BigInteger getR() {
        return r;
    }

    public void setR(BigInteger r) {
        this.r = r;
    }
}