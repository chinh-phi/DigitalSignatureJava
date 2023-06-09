/*
 * Copyright 2018 trident.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package ecdsa.elliptic;

import ecdsa.elliptic.nist.SECP;
import ecdsa.field.element.BinaryExtensionFieldElement;
import ecdsa.field.element.BinaryExtensionFieldElementFactory;
import ecdsa.field.element.FiniteFieldElement;
import ecdsa.field.element.FiniteFieldElementFactory;
import ecdsa.field.operator.FiniteFieldElementArithmetics;

import java.math.BigInteger;

/**
 * @see <a href="http://www.secg.org/SEC2-Ver-1.0.pdf">...</a>
 */
public class EllipticCurve{
    
    /**
     * parameter a of the curve equation 
     */
    private final FiniteFieldElement a;
    
    /**
     * parameter b of the curve equation 
     */
    private final FiniteFieldElement b;
    
    /**
     * point on the curve with high order
     */
    private final EllipticCurvePoint G;
    
    /**
     * order of the point G
     */
    private final BigInteger n;
    
    /**
     * cofactor - relation between number of points of curve and order of point G
     */
    private final BigInteger h;
    
    /**
     * arithmetics of the finite field over which this curve is defined
     * i.e. GF(p) or GF(2^m)
     */
    private final FiniteFieldElementArithmetics fieldArithmetics;

    public EllipticCurve(FiniteFieldElementArithmetics fieldArithmetics, FiniteFieldElement a, FiniteFieldElement b, EllipticCurvePoint G, BigInteger n, BigInteger h) {
        this.a = a;
        this.b = b;
        this.G = G;
        this.n = n;
        this.h = h;
        this.fieldArithmetics = fieldArithmetics;
    }

    public FiniteFieldElementArithmetics getFieldArithmetics() {
        return fieldArithmetics;
    }

    public FiniteFieldElement getA() {
        return a;
    }

    public FiniteFieldElement getB() {
        return b;
    }

    public EllipticCurvePoint getG() {
        return G;
    }
    
    public BigInteger getN() {
        return n;
    }

    public BigInteger getH() {
        return h;
    }   
    
    @Override
    public String toString(){
        StringBuilder sb = new StringBuilder();
        sb.append("Elliptic curve with:")
                .append("\n")
                .append(getFieldArithmetics())
                .append("\n")
                .append("With params:\n")
                .append("A = ")
                .append(getA())
                .append("\n")
                .append("B = ")
                .append(getB())
                .append("\n")
                .append("G = ")
                .append(getG())
                .append("\n")
                .append("n = ")
                .append(getN())
                .append("\n")
                .append("H = ")
                .append(getH())
                .append("\n");      
        return sb.toString();
    }   
    
    /**
     * static factory method producing elliptic curve from 
     * standard specification
     * 
     * should prefer this over custom constructor call
     * @param spec
     * @return 
     */
    public static EllipticCurve createFrom(SECP spec){
        return createFrom(spec, spec.getType()?new FiniteFieldElementFactory():new BinaryExtensionFieldElementFactory());
    }
    
    private static EllipticCurve createFrom(SECP spec, FiniteFieldElementFactory factory){
        FiniteFieldElementArithmetics arithmetics = 
                FiniteFieldElementArithmetics.createFieldElementArithmetics(spec.getType()?new BigInteger(spec.getP(),16): BinaryExtensionFieldElement.fromString(spec.getP()));
        
        return new EllipticCurve(arithmetics,
                factory.createFrom(spec.getA()),
                factory.createFrom(spec.getB()),
                EllipticCurvePoint.create(factory.createFrom(spec.getGx()), factory.createFrom(spec.getGy())),
                spec.getN(),
                spec.getH());
    }   
}
