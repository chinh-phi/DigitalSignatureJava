package key;

import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.DERSequence;

import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidKeyException;

public class RSAPublicKey implements PublicKey {
    private BigInteger n; //RSA modulus
    private BigInteger e; //RSA public exponent

    public RSAPublicKey(BigInteger modulus, BigInteger exponent) throws InvalidKeyException {
        if (exponent.compareTo(BigInteger.valueOf(3)) == -1 || exponent.compareTo(modulus) >= 0) {
            throw new InvalidKeyException();
        }
        n = modulus;
        e = exponent;
    }

    public BigInteger getModulus() {
        return n;
    }

    public BigInteger getPublicExponent() {
        return e;
    }

    public byte[] getEncoded() throws IOException { //DER encoding of public key
        ASN1Integer[] integers = {new ASN1Integer(n), new ASN1Integer(e)};
        DERSequence sequence = new DERSequence(integers);
        return sequence.getEncoded();
    }
}
