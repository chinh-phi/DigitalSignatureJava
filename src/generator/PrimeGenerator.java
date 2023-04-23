package generator;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Random;

public class PrimeGenerator {

    // The Miller-Rabin test to check if a number is probably prime
    public static boolean isProbablyPrime(BigInteger n, int k) {
        if (n.compareTo(BigInteger.ONE) == 0 || n.compareTo(BigInteger.valueOf(4)) == 0) {
            return true;
        }
        if (n.mod(BigInteger.TWO).compareTo(BigInteger.ZERO) == 0) {
            return false;
        }

        // Write n - 1 as 2^r * d
        BigInteger d = n.subtract(BigInteger.ONE);
        int r = 0;
        while (d.mod(BigInteger.TWO).compareTo(BigInteger.ZERO) == 0) {
            r++;
            d = d.divide(BigInteger.TWO);
        }

        // Test k times
        for (int i = 0; i < k; i++) {
            BigInteger a = randomBigInteger(BigInteger.TWO, n.subtract(BigInteger.TWO));
            BigInteger x = a.modPow(d, n);
            if (x.compareTo(BigInteger.ONE) == 0 || x.compareTo(n.subtract(BigInteger.ONE)) == 0) {
                continue;
            }
            for (int j = 0; j < r - 1; j++) {
                x = x.modPow(BigInteger.TWO, n);
                if (x.compareTo(BigInteger.ONE) == 0) {
                    return false;
                }
                if (x.compareTo(n.subtract(BigInteger.ONE)) == 0) {
                    break;
                }
            }
            if (x.compareTo(n.subtract(BigInteger.ONE)) != 0) {
                return false;
            }
        }

        return true;
    }

    // Generate a big prime number
    public static BigInteger generatePrime(int bitLength, SecureRandom random) {
        BigInteger prime = BigInteger.ZERO;

        while (!isProbablyPrime(prime, 64)) {
            prime = new BigInteger(bitLength, random);
        }

        return prime;
    }

    // A helper method to generate a random BigInteger between two values
    public static BigInteger randomBigInteger(BigInteger min, BigInteger max) {
        BigInteger range = max.subtract(min).add(BigInteger.ONE);
        return new BigInteger(range.bitLength(), new Random()).mod(range).add(min);
    }
}

