package key;

import java.math.BigInteger;

public class ElgamalPublicKey implements PublicKey {
    private BigInteger y;

    private BigInteger g;

    private BigInteger p;

    public ElgamalPublicKey(BigInteger y, BigInteger g, BigInteger p) {
        this.y = y;
        this.g = g;
        this.p = p;
    }

    public BigInteger getY() {
        return y;
    }

    public BigInteger getG() {
        return g;
    }

    public BigInteger getP() {
        return p;
    }
}
