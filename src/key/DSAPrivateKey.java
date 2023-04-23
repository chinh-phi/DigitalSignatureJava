package key;

import java.math.BigInteger;

public class DSAPrivateKey implements PrivateKey {
    private BigInteger x;
    private BigInteger p;
    private BigInteger q;
    private BigInteger g;

    public DSAPrivateKey(BigInteger x, BigInteger p, BigInteger q, BigInteger g) {
        this.x = x;
        this.p = p;
        this.q = q;
        this.g = g;
    }

    public BigInteger getX() {
        return x;
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
