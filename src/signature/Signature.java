package signature;

import key.PrivateKey;
import key.PublicKey;

import java.security.SignatureException;

public abstract class Signature {

    public final void initSign(PrivateKey privateKey) {
        engineInitSign(privateKey);
    }

    protected abstract void engineInitSign(PrivateKey privateKey);

    public final void update(byte[] data) {
        engineUpdate(data);
    }

    protected abstract void engineUpdate(byte[] data);

    public final byte[] sign() {
        return engineSign();
    }

    protected abstract byte[] engineSign();

    public final void initVerify(PublicKey publicKey) {
        engineInitVerify(publicKey);
    }

    protected abstract void engineInitVerify(PublicKey publicKey);

    public final boolean verify(byte[] signature) throws SignatureException {
        return engineVerify(signature);
    }

    protected abstract boolean engineVerify(byte[] sigBytes);
}
