package generator;

import key.KeyPair;
import key.RSAPrivateKey;
import key.RSAPublicKey;

import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.SecureRandom;

public class RSAKeyPairGenerator implements KeyPairGenerator {
    private BigInteger publicExponent;

    // size of the key to generate, >= RSAKeyFactory.MIN_MODLEN
    private int keySize;
    private SecureRandom random;
    public void initialize(int keysize, SecureRandom random) {
        this.keySize = keysize;
        this.publicExponent = BigInteger.valueOf(65537);
        this.random = random;
    }

    public KeyPair generateKeyPair() {
        int lp = (keySize + 1) >> 1;
        int lq = keySize - lp;
        if (random == null) {
            random = new SecureRandom();
        }
        BigInteger e = publicExponent;
        while (true) {
            // generate two random primes of size lp/lq
            BigInteger p = PrimeGenerator.generatePrime(lp, new SecureRandom());
            BigInteger q, n;
            do {
                q = PrimeGenerator.generatePrime(lq, new SecureRandom());
                // convention is for p > q
                if (p.compareTo(q) < 0) {
                    BigInteger tmp = p;
                    p = q;
                    q = tmp;
                }
                // modulus n = p * q
                n = p.multiply(q);
                // even with correctly sized p and q, there is a chance that
                // n will be one bit short. re-generate the smaller prime if so
            } while (n.bitLength() < keySize);

            // phi = (p - 1) * (q - 1) must be relative prime to e
            // otherwise RSA just won't work ;-)
            BigInteger p1 = p.subtract(BigInteger.ONE);
            BigInteger q1 = q.subtract(BigInteger.ONE);
            BigInteger phi = p1.multiply(q1);
            // generate new p and q until they work. typically
            // the first try will succeed when using F4
            if (!e.gcd(phi).equals(BigInteger.ONE)) {
                continue;
            }

            // private exponent d is the inverse of e mod phi
            BigInteger d = e.modInverse(phi);

            RSAPublicKey publicKey = null;
            try {
                publicKey = new RSAPublicKey(n, e);
            } catch (InvalidKeyException ex) {
                throw new RuntimeException(ex);
            }
            RSAPrivateKey privateKey = null;
            try {
                privateKey = new RSAPrivateKey(n, d);
            } catch (InvalidKeyException ex) {
                throw new RuntimeException(ex);
            }
            return new KeyPair(privateKey, publicKey);
        }
    }
}
