package key;

import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.DERSequence;

import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidKeyException;

public class RSAPrivateKey implements PrivateKey {

    private BigInteger n; //RSA modulus
    private BigInteger d; //RSA private exponent

    public RSAPrivateKey(BigInteger modulus, BigInteger exponent) throws InvalidKeyException {
        if (exponent.compareTo(modulus) >= 0) {
            throw new InvalidKeyException();
        }
        n = modulus;
        d = exponent;
    }

    public BigInteger getModulus() {
        return n;
    }

    public BigInteger getPrivateExponent() {
        return d;
    }

    public byte[] getEncoded() throws IOException { //DER encoding of private key
        ASN1Integer[] integers = {new ASN1Integer(n), new ASN1Integer(d)};
        DERSequence sequence = new DERSequence(integers);
        return sequence.getEncoded();
    }
}
