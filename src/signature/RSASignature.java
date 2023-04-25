package signature;

import key.PrivateKey;
import key.PublicKey;
import key.RSAPrivateKey;
import key.RSAPublicKey;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;

public class RSASignature extends Signature {

    private static final SecureRandom random = new SecureRandom();
    private RSAPrivateKey privateKey;
    private RSAPublicKey publicKey;
    private byte[] paddedMessage;
    private byte[] message;

    public static byte[]    SHA256(byte[] input) throws NoSuchAlgorithmException {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        return digest.digest(input);
    }

    public static byte[] MGF1(byte[] seed, int seedOffset, int seedLength, int desiredLength) throws NoSuchAlgorithmException {
        int hLen = 32;
        int offset = 0;
        int i = 0;
        byte[] mask = new byte[desiredLength];
        byte[] temp = new byte[seedLength + 4];
        System.arraycopy(seed, seedOffset, temp, 4, seedLength);
        while (offset < desiredLength) {
            temp[0] = (byte) (i >>> 24);
            temp[1] = (byte) (i >>> 16);
            temp[2] = (byte) (i >>> 8);
            temp[3] = (byte) i;
            int remaining = desiredLength - offset;
            System.arraycopy(SHA256(temp), 0, mask, offset, remaining < hLen ? remaining : hLen);
            offset = offset + hLen;
            i = i + 1;
        }
        return mask;
    }

    public byte[] padOEAP(byte[] message, String params, int length) throws Exception {
        String[] tokens = params.split(" ");
        if (tokens.length != 2 || !tokens[0].equals("SHA-256") || !tokens[1].equals("MGF1")) {
            return null;
        }
        int mLen = message.length;
        int hLen = 32;
        if (mLen > length - (hLen << 1) - 1) {
            return null;
        }
        int zeroPad = length - mLen - (hLen << 1) - 1;
        byte[] dataBlock = new byte[length - hLen];
        System.arraycopy(SHA256(params.getBytes("UTF-8")), 0, dataBlock, 0, hLen);
        System.arraycopy(message, 0, dataBlock, hLen + zeroPad + 1, mLen);
        dataBlock[hLen + zeroPad] = 1;
        byte[] seed = new byte[hLen];
        random.nextBytes(seed);
        byte[] dataBlockMask = MGF1(seed, 0, hLen, length - hLen);
        for (int i = 0; i < length - hLen; i++) {
            dataBlock[i] ^= dataBlockMask[i];
        }
        byte[] seedMask = MGF1(dataBlock, 0, length - hLen, hLen);
        for (int i = 0; i < hLen; i++) {
            seed[i] ^= seedMask[i];
        }
        byte[] padded = new byte[length];
        System.arraycopy(seed, 0, padded, 0, hLen);
        System.arraycopy(dataBlock, 0, padded, hLen, length - hLen);
        return padded;
    }

    public byte[] unpadOEAP(byte[] message, String params) throws Exception {
        String[] tokens = params.split(" ");
        if (tokens.length != 2 || !tokens[0].equals("SHA-256") || !tokens[1].equals("MGF1")) {
            return null;
        }
        int mLen = message.length;
        int hLen = 32;
        if (mLen < (hLen << 1) + 1) {
            return null;
        }
        byte[] copy = new byte[mLen];
        System.arraycopy(message, 0, copy, 0, mLen);
        byte[] seedMask = MGF1(copy, hLen, mLen - hLen, hLen);
        for (int i = 0; i < hLen; i++) {
            copy[i] ^= seedMask[i];
        }
        byte[] paramsHash = SHA256(params.getBytes("UTF-8"));
        byte[] dataBlockMask = MGF1(copy, 0, hLen, mLen - hLen);
        int index = -1;
        for (int i = hLen; i < mLen; i++) {
            copy[i] ^= dataBlockMask[i - hLen];
            if (i < (hLen << 1)) {
                if (copy[i] != paramsHash[i - hLen]) {
                    return null;
                }
            } else if (index == -1) {
                if (copy[i] == 1) {
                    index = i + 1;
                }
            }
        }
        if (index == -1 || index == mLen) {
            return null;
        }
        byte[] unpadded = new byte[mLen - index];
        System.arraycopy(copy, index, unpadded, 0, mLen - index);
        return unpadded;
    }

    @Override
    protected void engineInitSign(PrivateKey privateKey) {
        this.privateKey = (RSAPrivateKey) privateKey;
        this.publicKey = null;
    }

    @Override
    protected void engineUpdate(byte[] data) {
        this.message = data;
    }

    @Override
    protected byte[] engineSign() {
        try {
            this.paddedMessage = padOEAP(message, "SHA-256 MGF1", 2048 / 8);
            BigInteger m = new BigInteger(1, paddedMessage);
            BigInteger s = m.modPow(privateKey.getPrivateExponent(), privateKey.getModulus());
            return s.toByteArray();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    protected void engineInitVerify(PublicKey publicKey) {
        this.privateKey = null;
        this.publicKey = (RSAPublicKey) publicKey;
    }

    @Override
    protected boolean engineVerify(byte[] sigBytes) {
        BigInteger m = new BigInteger(1, paddedMessage);
        BigInteger s = new BigInteger(1, sigBytes);
        BigInteger v = s.modPow(publicKey.getPublicExponent(), publicKey.getModulus());
        byte[] text = new byte[0];
        try {
            text = unpadOEAP(paddedMessage, "SHA-256 MGF1");
            return Arrays.equals(text, message) && v.equals(m);
        } catch (Exception ex) {
            throw new RuntimeException(ex);
        }
    }
}
