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
package ecdsa.field;

import java.math.BigInteger;

/**
 *
 */
public class PrimeField extends FiniteField{
    
    public PrimeField(BigInteger orderP) {
        super(orderP, orderP);
    }
    
    @Override
    public String toString(){
        return "Prime field over "+getOrderP();
    }

    @Override
    public BigInteger getOrder() {
        return getOrderP();
    }
    
}
