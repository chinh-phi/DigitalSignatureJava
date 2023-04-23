package spec.dsa;

import java.math.BigInteger;

public class DSAParameterSpec {
    BigInteger p;
    BigInteger q;
    BigInteger g;

    public DSAParameterSpec(BigInteger p, BigInteger q, BigInteger g) {
        this.p = p;
        this.q = q;
        this.g = g;
    }

    public BigInteger getP() {
        return p;
    }

    public BigInteger getQ() {
        return q;
    }

    public BigInteger getG() {
        return g;
    }
}
