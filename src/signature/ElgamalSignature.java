package signature;

import key.ElgamalPrivateKey;
import key.ElgamalPublicKey;
import key.PrivateKey;
import key.PublicKey;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

public class ElgamalSignature extends Signature{
    private BigInteger r;
    private BigInteger s;
    private ElgamalPrivateKey privateKey;
    private ElgamalPublicKey publicKey;
    private byte[] message;

    public static byte[] hash(byte[] input) throws NoSuchAlgorithmException {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        return digest.digest(input);
    }

    @Override
    protected void engineInitSign(PrivateKey privateKey) {
        this.privateKey = (ElgamalPrivateKey) privateKey;
        this.publicKey = null;
    }

    @Override
    protected void engineUpdate(byte[] data) {
        this.message = data;
    }

    @Override
    protected byte[] engineSign() {
        SecureRandom random = new SecureRandom();
        BigInteger k = new BigInteger(privateKey.getP().bitLength(), random); // random k such that 1 <= k <= p-2
        while (k.equals(BigInteger.ZERO)) {
            k = new BigInteger(privateKey.getP().bitLength() - 1, random);
        }
        BigInteger r = privateKey.getG().modPow(k, privateKey.getP());
        BigInteger m = null; // hash message with SHA-256
        try {
            m = new BigInteger(1, hash(message));
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
        BigInteger s = m.subtract(privateKey.getX().multiply(r))
                .multiply(k.modInverse(privateKey.getP().subtract(BigInteger.ONE)))
                .mod(privateKey.getP().subtract(BigInteger.ONE));
        this.r = r;
        this.s = s;

        return new byte[0];
    }

    @Override
    protected void engineInitVerify(PublicKey publicKey) {
        ElgamalPublicKey rsaKey = (ElgamalPublicKey) publicKey;
        this.privateKey = null;
        this.publicKey = rsaKey;
    }

    @Override
    protected boolean engineVerify(byte[] sigBytes) {
        BigInteger m = null; // hash message with SHA-256
        try {
            m = new BigInteger(1, hash(message));
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
        BigInteger v1 = publicKey.getG().modPow(m, publicKey.getP());
        BigInteger v2 = publicKey.getY()
                .modPow(this.r, publicKey.getP())
                .multiply(this.r.modPow(this.s, publicKey.getP()))
                .mod(publicKey.getP());
        return v1.equals(v2);
    }
}
