package signature;

import key.DSAPrivateKey;
import key.DSAPublicKey;
import key.PrivateKey;
import key.PublicKey;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

public class DSASignature extends Signature{

    private DSAPrivateKey privateKey;
    private DSAPublicKey publicKey;
    private byte[] message;

    @Override
    protected void engineInitSign(PrivateKey privateKey) {
        this.privateKey = (DSAPrivateKey) privateKey;
        this.publicKey = null;
    }

    @Override
    protected void engineUpdate(byte[] data) {
        this.message = data;
    }

    @Override
    protected byte[] engineSign() {
        BigInteger k;
        BigInteger r;
        BigInteger s;
        do {
            k = new BigInteger(privateKey.getQ().bitLength(), new SecureRandom());
            r = privateKey.getG().modPow(k, privateKey.getP()).mod(privateKey.getQ());
            BigInteger hash = null;
            try {
                hash = sha256(message);
            } catch (NoSuchAlgorithmException e) {
                throw new RuntimeException(e);
            }
            BigInteger xR = privateKey.getX().multiply(r);
            BigInteger xRPlusHash = xR.add(hash);
            s = k.modInverse(privateKey.getQ()).multiply(xRPlusHash).mod(privateKey.getQ());
        } while (r.equals(BigInteger.ZERO) || s.equals(BigInteger.ZERO));

        byte[] rBytes = r.toByteArray();
        byte[] sBytes = s.toByteArray();

        int signatureLength = rBytes.length + sBytes.length;
        byte[] signature = new byte[signatureLength];
        System.arraycopy(rBytes, 0, signature, 0, rBytes.length);
        System.arraycopy(sBytes, 0, signature, rBytes.length, sBytes.length);
        return signature;
    }

    @Override
    protected void engineInitVerify(PublicKey publicKey) {
        this.privateKey = null;
        this.publicKey = (DSAPublicKey) publicKey;
    }

    @Override
    protected boolean engineVerify(byte[] sigBytes) {
        int halfLength = sigBytes.length / 2;
        byte[] rBytes = new byte[halfLength];
        byte[] sBytes = new byte[halfLength];
        System.arraycopy(sigBytes, 0, rBytes, 0, halfLength);
        System.arraycopy(sigBytes, halfLength, sBytes, 0, halfLength);

        BigInteger r = new BigInteger(1, rBytes);
        BigInteger s = new BigInteger(1, sBytes);

        if (r.compareTo(publicKey.getQ()) >= 0 || s.compareTo(publicKey.getQ()) >= 0) {
            return false;
        }

        BigInteger w = s.modInverse(publicKey.getQ());
        BigInteger hash = null;
        try {
            hash = sha256(message);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
        BigInteger u1 = hash.multiply(w).mod(publicKey.getQ());
        BigInteger u2 = r.multiply(w).mod(publicKey.getQ());
        BigInteger v = publicKey.getG()
                .modPow(u1, publicKey.getP())
                .multiply(publicKey.getY().modPow(u2, publicKey.getP()))
                .mod(publicKey.getP())
                .mod(publicKey.getQ());

        return v.equals(r);
    }

    private static BigInteger sha256(byte[] message) throws NoSuchAlgorithmException {
        MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
        sha256.update(message);
        byte[] digest = sha256.digest();
        return new BigInteger(1, digest);
    }
}
