package key;

import ecdsa.elliptic.EllipticCurveOperator;

import java.math.BigInteger;

public class ECDSAPrivateKey implements PrivateKey{
    /**
     * secret key b -> random BigInteger
     */
    private final BigInteger keySec;

    private final EllipticCurveOperator operator;

    public ECDSAPrivateKey(BigInteger keySec, EllipticCurveOperator operator) {
        this.keySec = keySec;
        this.operator = operator;
    }

    public BigInteger getKeySec() {
        return keySec;
    }

    public EllipticCurveOperator getOperator() {
        return operator;
    }
}
