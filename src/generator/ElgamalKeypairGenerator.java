package generator;

import key.ElgamalPrivateKey;
import key.ElgamalPublicKey;
import key.KeyPair;

import java.math.BigInteger;
import java.security.SecureRandom;

public class ElgamalKeypairGenerator implements KeyPairGenerator{
    private int keySize;
    public void initialize(int keySize) {
        this.keySize = keySize;
    }

    private static final SecureRandom random = new SecureRandom();

    @Override
    public KeyPair generateKeyPair() {

        BigInteger p, g, x, y;
        do {
            p = BigInteger.probablePrime(1024, random);
            g = generateGenerator(p, random);
            x = new BigInteger(keySize - 1, random);
            y = g.modPow(x, p);
        } while (y.bitLength() != keySize);

        ElgamalPublicKey publicKey = new ElgamalPublicKey(y, g, p);
        ElgamalPrivateKey privateKey = new ElgamalPrivateKey(x, g, p);

        return new KeyPair(privateKey, publicKey);
    }

    private static BigInteger generateGenerator(BigInteger p, SecureRandom random) {
        BigInteger g;
        do {
            g = new BigInteger(p.bitLength(), random);
        } while (g.compareTo(BigInteger.ONE) <= 0 || g.compareTo(p.subtract(BigInteger.ONE)) >= 0 || !g.modPow(p.subtract(BigInteger.ONE).divide(BigInteger.TWO), p).equals(BigInteger.ONE));
        return g;
    }
}
