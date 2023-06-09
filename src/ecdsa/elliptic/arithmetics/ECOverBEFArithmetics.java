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
package ecdsa.elliptic.arithmetics;

import ecdsa.elliptic.EllipticCurve;
import ecdsa.elliptic.EllipticCurvePoint;
import ecdsa.field.element.FiniteFieldElement;
import ecdsa.field.operator.FiniteFieldElementArithmetics;

/**
 * for elliptic curves over prime finite fields the 
 * y^2 +xy = x^3 +ax^2 + b equation is used
 */
public class ECOverBEFArithmetics extends EllipticCurveArithmetics{
    
     public ECOverBEFArithmetics(EllipticCurve ellipticCurve) {
        super(ellipticCurve);
    }

    @Override
    public EllipticCurvePoint add(EllipticCurvePoint p1, EllipticCurvePoint p2) {
        if(p1.equals(p2)) return doub(p1);
        FiniteFieldElementArithmetics f = ellipticCurve.getFieldArithmetics();
        FiniteFieldElement dy = f.add(p2.getPointY(), p1.getPointY()); //p2.y + p1.y
        FiniteFieldElement dx = f.add(p2.getPointX(), p1.getPointX()); //p2.x + p1.x 
        FiniteFieldElement m  = f.mul(dy, f.inv(dx)); // dy/dx
        FiniteFieldElement p3x =
                f.add(
                        f.add(f.add(f.add(f.mul(m, m),p1.getPointX()),p2.getPointX()),getEllipticCurve().getA()),
                        m
                ); // m^2 + m + p1.x + p2.x + a
        FiniteFieldElement p3y =
                f.add(f.add(f.mul(m, f.add(p1.getPointX(), p3x)),p1.getPointY()),p3x); // m*(p1.x + p3.x) + p3.x + p1.y
        return EllipticCurvePoint.create(p3x, p3y);
    }

    @Override
    public EllipticCurvePoint doub(EllipticCurvePoint p1) {
        FiniteFieldElementArithmetics f = ellipticCurve.getFieldArithmetics();
        FiniteFieldElement m  = f.add(f.mul(p1.getPointY(), f.inv(p1.getPointX())),p1.getPointX()); // m = p1.x + p1.y/p1.x
        FiniteFieldElement p3x = f.add(f.add(f.mul(m, m),m),getEllipticCurve().getA()); // m^2 + m + a
        FiniteFieldElement p3y = f.add(f.add(f.mul(p1.getPointX(), p1.getPointX()),p3x),f.mul(m, p3x)); // p1.x^2 + m*p3.x + p3.x
        return EllipticCurvePoint.create(p3x, p3y);
    }

    /**
     * 
     * @param p1 - elliptic curve point
     * @return true if y^2 +xy = x^3 +ax^2 + b for p1
     */
    @Override
    public boolean belongsTo(EllipticCurvePoint p1) {
        FiniteFieldElementArithmetics f = ellipticCurve.getFieldArithmetics();
        FiniteFieldElement y2 = f.mul(p1.getPointY(), p1.getPointY()); //y^2
        FiniteFieldElement xy = f.mul(p1.getPointX(), p1.getPointY()); //xy
        FiniteFieldElement lp = f.add(y2, xy); //y^2+xy
        FiniteFieldElement x2 = f.mul(p1.getPointX(), p1.getPointX()); //x^2
        FiniteFieldElement x3 = f.mul(x2,p1.getPointX()); // x^3
        FiniteFieldElement ax2 = f.mul(x2, getEllipticCurve().getA()); // ax^2
        FiniteFieldElement res = f.add(f.add(x3, ax2),getEllipticCurve().getB()); // x^3+ax^2+b
        return lp.equals(res); // y^2 +xy = x^3 +ax^2 + b
    }

    @Override
    public EllipticCurvePoint negate(EllipticCurvePoint p1) {
        FiniteFieldElementArithmetics f = ellipticCurve.getFieldArithmetics();
        return EllipticCurvePoint.create(p1.getPointX(), f.add(p1.getPointX(), p1.getPointY()));
    }
}
