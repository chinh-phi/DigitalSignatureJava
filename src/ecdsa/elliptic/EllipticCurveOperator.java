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

import java.math.BigInteger;

/**
 * defines the operations on elliptic curve point
 */
public interface EllipticCurveOperator {
    /**
     * add two elliptic curve points
     * @param p1
     * @param p2
     * @return the point p3 = p1 + p2 which also belongs to the elliptic curve
     */
    EllipticCurvePoint add(EllipticCurvePoint p1, EllipticCurvePoint p2);
    
    /**
     * multiply elliptic curve point to the number
     * in fact add point k times to itself
     * i.e. Q = k*P
     * @param times - number k in k*P
     * @param p1 - point P in k*P
     * @return Q = k*P
     */
    EllipticCurvePoint mul(BigInteger times, EllipticCurvePoint p1);
    
    /**
     * double provided point,
     * i.e. calculate Q = 2P;
     * @param p1 - point of the elliptic curve
     * @return Q = 2*P
     */
    EllipticCurvePoint doub(EllipticCurvePoint p1);
    
    /**
     * check if the provided point belongs to this elliptic curve
     * @param p1
     * @return 
     */
    boolean belongsTo(EllipticCurvePoint p1);
    
    /**
     * negate the point, i.e. return -P
     * @param p1
     * @return -p1
     */
    EllipticCurvePoint negate(EllipticCurvePoint p1);
    
    /**
     * return elliptic curve over which the operations are performed
     * @return 
     */
    EllipticCurve getEllipticCurve();
    
}
