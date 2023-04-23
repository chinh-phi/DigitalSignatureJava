package generator;

import ecdsa.algo.mpmbehavior.MPMBehavior;
import ecdsa.algo.mpmbehavior.MPMStandardBehavior;
import ecdsa.elliptic.EllipticCurveOperator;
import ecdsa.elliptic.EllipticCurvePoint;
import ecdsa.elliptic.arithmetics.EllipticCurveArithmetics;
import key.ECDSAPrivateKey;
import key.ECDSAPublicKey;
import key.KeyPair;

import java.math.BigInteger;
import java.util.Random;

public class ECDSAKeyPairGenerator implements KeyPairGenerator {
    /**
     * arithmetics over the elliptic curve
     * @see EllipticCurveArithmetics
     */
    private final EllipticCurveOperator operator;

    /**
     * multiple point multiplication calculation strategy
     */
    private MPMBehavior mpmBehavior;

    private final Random random;

    public ECDSAKeyPairGenerator(EllipticCurveOperator operator, MPMBehavior behavior){
        this.operator = operator;
        this.random = new Random();
        this.mpmBehavior = behavior;
    }

    public ECDSAKeyPairGenerator(EllipticCurveOperator operator){
        this(operator, new MPMStandardBehavior(operator));
    }

    @Override
    public KeyPair generateKeyPair() {
        BigInteger sKey = new BigInteger(getOperator().getEllipticCurve().getN().bitLength(), random);
        ECDSAPrivateKey privateKey = new ECDSAPrivateKey(sKey, getOperator());
        EllipticCurvePoint pKey = getOperator().mul(sKey, getOperator().getEllipticCurve().getG());
        ECDSAPublicKey publicKey = new ECDSAPublicKey(pKey, getOperator());
        return new KeyPair(privateKey, publicKey);
    }

    private EllipticCurveOperator getOperator() {
        return operator;
    }

    public Random getRandom() {
        return random;
    }
}
