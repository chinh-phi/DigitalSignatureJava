package key;

import java.math.BigInteger;

public class DSAPublicKey implements PublicKey {

    private BigInteger y;
    private BigInteger p;
    private BigInteger q;
    private BigInteger g;

    public DSAPublicKey(BigInteger y, BigInteger p, BigInteger q, BigInteger g) {
        this.y = y;
        this.p = p;
        this.q = q;
        this.g = g;
    }

    public BigInteger getY() {
        return y;
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
