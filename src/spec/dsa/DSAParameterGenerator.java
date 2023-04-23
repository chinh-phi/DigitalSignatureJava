package spec.dsa;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.ProviderException;
import java.security.SecureRandom;

public class DSAParameterGenerator {
    private static final int L = 1024; // security parameter
    private static final int N = 160; // size of q parameter
    private static final SecureRandom random = new SecureRandom();

    public static DSAParameterSpec generateDSAParameterSpec() {

        BigInteger[] pAndQ = generatePandQ(random, L, N, 160);
        BigInteger p = pAndQ[0];
        BigInteger q = pAndQ[1];
        BigInteger g = generateG(p, q);

        return new DSAParameterSpec(p, q, g);
    }

    private static BigInteger[] generatePandQ(SecureRandom random, int valueL,
                                              int valueN, int seedLen) {
        String hashAlg = null;
        if (valueN == 160) {
            hashAlg = "SHA";
        } else if (valueN == 224) {
            hashAlg = "SHA-224";
        } else if (valueN == 256) {
            hashAlg = "SHA-256";
        }
        MessageDigest hashObj = null;
        try {
            hashObj = MessageDigest.getInstance(hashAlg);
        } catch (NoSuchAlgorithmException nsae) {
            // should never happen
            nsae.printStackTrace();
        }

        /* Step 3, 4: Useful variables */
        int outLen = hashObj.getDigestLength()*8;
        int n = (valueL - 1) / outLen;
        int b = (valueL - 1) % outLen;
        byte[] seedBytes = new byte[seedLen/8];
        BigInteger twoSl = BigInteger.TWO.pow(seedLen);
        int primeCertainty = -1;
        if (valueL <= 1024) {
            primeCertainty = 80;
        } else if (valueL == 2048) {
            primeCertainty = 112;
        } else if (valueL == 3072) {
            primeCertainty = 128;
        }
        if (primeCertainty < 0) {
            throw new ProviderException("Invalid valueL: " + valueL);
        }
        BigInteger resultP, resultQ, seed = null;
        int counter;
        while (true) {
            do {
                /* Step 5 */
                random.nextBytes(seedBytes);
                seed = new BigInteger(1, seedBytes);

                /* Step 6 */
                BigInteger U = new BigInteger(1, hashObj.digest(seedBytes)).
                        mod(BigInteger.TWO.pow(valueN - 1));

                /* Step 7 */
                resultQ = BigInteger.TWO.pow(valueN - 1)
                        .add(U)
                        .add(BigInteger.ONE)
                        .subtract(U.mod(BigInteger.TWO));
            } while (!resultQ.isProbablePrime(primeCertainty));

            /* Step 10 */
            BigInteger offset = BigInteger.ONE;
            /* Step 11 */
            for (counter = 0; counter < 4*valueL; counter++) {
                BigInteger[] V = new BigInteger[n + 1];
                /* Step 11.1 */
                for (int j = 0; j <= n; j++) {
                    BigInteger J = BigInteger.valueOf(j);
                    BigInteger tmp = (seed.add(offset).add(J)).mod(twoSl);
                    byte[] vjBytes = hashObj.digest(toByteArray(tmp));
                    V[j] = new BigInteger(1, vjBytes);
                }
                /* Step 11.2 */
                BigInteger W = V[0];
                for (int i = 1; i < n; i++) {
                    W = W.add(V[i].multiply(BigInteger.TWO.pow(i * outLen)));
                }
                W = W.add((V[n].mod(BigInteger.TWO.pow(b)))
                        .multiply(BigInteger.TWO.pow(n * outLen)));
                /* Step 11.3 */
                BigInteger twoLm1 = BigInteger.TWO.pow(valueL - 1);
                BigInteger X = W.add(twoLm1);
                /* Step 11.4, 11.5 */
                BigInteger c = X.mod(resultQ.multiply(BigInteger.TWO));
                resultP = X.subtract(c.subtract(BigInteger.ONE));
                /* Step 11.6, 11.7 */
                if (resultP.compareTo(twoLm1) > -1
                        && resultP.isProbablePrime(primeCertainty)) {
                    /* Step 11.8 */
                    BigInteger[] result = {resultP, resultQ, seed,
                            BigInteger.valueOf(counter)};
                    return result;
                }
                /* Step 11.9 */
                offset = offset.add(BigInteger.valueOf(n)).add(BigInteger.ONE);
            }
        }

    }

    private static BigInteger generateG(BigInteger p, BigInteger q) {
        BigInteger h = BigInteger.ONE;
        /* Step 1 */
        BigInteger pMinusOneOverQ = (p.subtract(BigInteger.ONE)).divide(q);
        BigInteger resultG = BigInteger.ONE;
        while (resultG.compareTo(BigInteger.TWO) < 0) {
            /* Step 3 */
            resultG = h.modPow(pMinusOneOverQ, p);
            h = h.add(BigInteger.ONE);
        }
        return resultG;
    }

    private static byte[] toByteArray(BigInteger bigInt) {
        byte[] result = bigInt.toByteArray();
        if (result[0] == 0) {
            byte[] tmp = new byte[result.length - 1];
            System.arraycopy(result, 1, tmp, 0, tmp.length);
            result = tmp;
        }
        return result;
    }
}
