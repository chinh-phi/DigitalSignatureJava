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
package ecdsa.algo.mpmbehavior;

import ecdsa.elliptic.EllipticCurveOperator;
import ecdsa.elliptic.EllipticCurvePoint;

import java.math.BigInteger;

/**
 *
 */
public final class MPMStandardBehavior implements MPMBehavior{
    
    private final EllipticCurveOperator operator;

    public MPMStandardBehavior(EllipticCurveOperator operator) {
        this.operator = operator;
    }

    @Override
    public EllipticCurvePoint mpm(BigInteger k, BigInteger l, EllipticCurvePoint P, EllipticCurvePoint Q) {
        return operator.add(operator.mul(k, P), operator.mul(l, Q));
    }
    
}
