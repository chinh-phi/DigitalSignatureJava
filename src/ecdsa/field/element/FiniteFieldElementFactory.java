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
package ecdsa.field.element;

import java.math.BigInteger;

/**
 * factory for creating finite field elements
 */
public class FiniteFieldElementFactory {
    /**
     * create the finite field element from BigInteger representation
     * @param value
     * @return 
     */
    public FiniteFieldElement createFrom(BigInteger value){
        if(value.signum()<0) throw new RuntimeException("biginteger should not be negative");
        return new FiniteFieldElement(value);
    }
}
