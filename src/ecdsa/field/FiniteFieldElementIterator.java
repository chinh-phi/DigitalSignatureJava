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

import ecdsa.field.element.FiniteFieldElement;
import ecdsa.field.operator.FiniteFieldElementArithmetics;

import java.math.BigInteger;
import java.util.Iterator;

/**
 *
 */
public class FiniteFieldElementIterator implements Iterator<FiniteFieldElement>{
    
    protected final FiniteFieldElementArithmetics arithmetics;
    private FiniteFieldElement current;
    
    public FiniteFieldElementIterator(FiniteFieldElementArithmetics arithmetics){
        this.arithmetics = arithmetics;
        this.current = arithmetics.getElementFactory().createFrom(BigInteger.ZERO);
    }

    @Override
    public boolean hasNext() {
        return true;
    }

    @Override
    public FiniteFieldElement next() {
        current = arithmetics.add(current, arithmetics.getElementFactory().createFrom(BigInteger.ONE));
        return current;
    }
    
}
