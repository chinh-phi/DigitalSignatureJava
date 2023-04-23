package key;

import ecdsa.elliptic.EllipticCurveOperator;
import ecdsa.elliptic.EllipticCurvePoint;

public class ECDSAPublicKey implements PublicKey {
    private final EllipticCurvePoint keyPub;

    private final EllipticCurveOperator operator;

    public ECDSAPublicKey(EllipticCurvePoint keyPub, EllipticCurveOperator operator) {
        this.keyPub = keyPub;
        this.operator = operator;
    }

    public EllipticCurvePoint getKeyPub() {
        return keyPub;
    }

    public EllipticCurveOperator getOperator() {
        return operator;
    }
}
