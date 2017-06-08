package prefix;

import java.math.BigInteger;
import java.util.List;

import static prefix.TestPrefix.THOUSAND;

class Prefix {

    BigInteger encode(BigInteger number, List<InnerPrefix> prefices) {
        int offset = number.add(new BigInteger(THOUSAND.toByteArray()).negate()).intValue();
        return prefices.get(offset).getR();
    }
}