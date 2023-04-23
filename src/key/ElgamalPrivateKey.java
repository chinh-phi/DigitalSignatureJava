package key;

import java.math.BigInteger;

public class ElgamalPrivateKey implements PrivateKey {
    private BigInteger x;
    private BigInteger g;
    private BigInteger p;

    public ElgamalPrivateKey(BigInteger x, BigInteger g, BigInteger p) {
        this.x = x;
        this.g = g;
        this.p = p;
    }

    public BigInteger getX() {
        return x;
    }

    public BigInteger getG() {
        return g;
    }

    public BigInteger getP() {
        return p;
    }
}
