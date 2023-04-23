package signature;

import ecdsa.algo.mpmbehavior.MPMBehavior;
import ecdsa.elliptic.EllipticCurvePoint;
import key.ECDSAPrivateKey;
import key.ECDSAPublicKey;
import key.PrivateKey;
import key.PublicKey;

import java.math.BigInteger;
import java.util.Random;

public class ECDSASignature extends Signature {
    private ECDSAPrivateKey privateKey;
    private ECDSAPublicKey publicKey;
    private BigInteger r;
    private BigInteger s;
    private MPMBehavior mpmBehavior;
    private byte[] message;

    public void initialize(MPMBehavior behavior) {
        this.mpmBehavior = behavior;
    }

    @Override
    protected void engineInitSign(PrivateKey privateKey) {
        this.privateKey = (ECDSAPrivateKey) privateKey;
        this.publicKey = null;
    }

    @Override
    protected void engineUpdate(byte[] data) {
        this.message = data;
    }

    @Override
    protected byte[] engineSign() {
        BigInteger n = privateKey.getOperator().getEllipticCurve().getN();
        EllipticCurvePoint G = privateKey.getOperator().getEllipticCurve().getG();

        BigInteger alpha = new BigInteger(message);
        BigInteger e = alpha.mod(n);
        if(e.equals(BigInteger.ZERO)) e = BigInteger.ONE;

        BigInteger k;
        EllipticCurvePoint C;
        BigInteger r;
        BigInteger s;
        do{
            do {
                k = new BigInteger(n.bitLength(), new Random());
            } while (k.compareTo(BigInteger.ZERO) == -1 || k.compareTo(n) >= 1); // k<0 || k>n
            C = privateKey.getOperator().mul(k, G);
            r = C.getPointX().mod(n);
            s = r.multiply(privateKey.getKeySec()).add(k.multiply(e)).mod(n);
        } while (r.equals(BigInteger.ZERO)||s.equals(BigInteger.ZERO));

        this.r = r;
        this.s = s;
        return new byte[0];
    }

    @Override
    protected void engineInitVerify(PublicKey publicKey) {
        this.privateKey = null;
        this.publicKey = (ECDSAPublicKey) publicKey;
    }

    @Override
    protected boolean engineVerify(byte[] sigBytes) {
        BigInteger n = publicKey.getOperator().getEllipticCurve().getN();
        EllipticCurvePoint G = publicKey.getOperator().getEllipticCurve().getG();

        if(r.compareTo(BigInteger.ZERO)<=0||r.compareTo(n)>=0) return false;
        if(s.compareTo(BigInteger.ZERO)<=0||s.compareTo(n)>=0) return false;

        BigInteger alpha = new BigInteger(message);
        BigInteger e = alpha.mod(n);
        if(e.equals(BigInteger.ZERO)) e = BigInteger.ONE;

        BigInteger v = e.modInverse(n);
        BigInteger z1 = (s.multiply(v)).mod(n);
        BigInteger z2 = n.add(r.multiply(v).negate()).mod(n);

        EllipticCurvePoint C = mpmBehavior.mpm(z1, z2, G, publicKey.getKeyPub());
        BigInteger R = C.getPointX().mod(n);

        return R.equals(r);
    }
}
