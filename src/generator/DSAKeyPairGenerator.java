package generator;

import key.DSAPrivateKey;
import key.DSAPublicKey;
import key.KeyPair;
import spec.dsa.DSAParameterGenerator;
import spec.dsa.DSAParameterSpec;

import java.math.BigInteger;
import java.security.SecureRandom;


public class DSAKeyPairGenerator implements KeyPairGenerator {
    @Override
    public KeyPair generateKeyPair() {
        DSAParameterSpec spec = DSAParameterGenerator.generateDSAParameterSpec();
        return generateKeyPair(spec.getP(), spec.getQ(), spec.getG(), new SecureRandom());
    }

    private KeyPair generateKeyPair(BigInteger p, BigInteger q, BigInteger g, SecureRandom random) {
        BigInteger x = generateX(random, q);
        BigInteger y = generateY(x, p, g);

        DSAPublicKey publicKey = new DSAPublicKey(y, p, q, g);
        DSAPrivateKey privateKey = new DSAPrivateKey(x, p , q, g);

        return new KeyPair(privateKey, publicKey);
    }

    private BigInteger generateX(SecureRandom random, BigInteger q) {
        BigInteger x = null;
        byte[] temp = new byte[160];
        while (true) {
            random.nextBytes(temp);
            x = new BigInteger(1, temp).mod(q);
            if (x.signum() > 0 && (x.compareTo(q) < 0)) {
                return x;
            }
        }
    }

    BigInteger generateY(BigInteger x, BigInteger p, BigInteger g) {
        BigInteger y = g.modPow(x, p);
        return y;
    }
}
