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
package ecdsa.field.operator;

import ecdsa.field.BinaryExtensionField;
import ecdsa.field.FiniteField;
import ecdsa.field.PrimeField;
import ecdsa.field.element.BinaryExtensionFieldElement;
import ecdsa.field.element.BinaryExtensionFieldElementFactory;
import ecdsa.field.element.FiniteFieldElement;
import ecdsa.field.element.FiniteFieldElementFactory;

import java.math.BigInteger;

/**
 * arithmetics of elements in prime field
 */
public abstract class FiniteFieldElementArithmetics{
    
    private final FiniteField field;
    private final FiniteFieldElementFactory elementFactory;
        
    FiniteFieldElementArithmetics(FiniteField field, FiniteFieldElementFactory elementFactory){
        this.field = field;
        this.elementFactory = elementFactory;
    }
    
    /**
     * add two finite field elements
     * @param el1
     * @param el2
     * @return sum of elements
     */
    public abstract FiniteFieldElement add(FiniteFieldElement el1, FiniteFieldElement el2);
    
    /**
     * subtract two finite field elements
     * @param el1
     * @param el2
     * @return 
     */
    public abstract FiniteFieldElement sub(FiniteFieldElement el1, FiniteFieldElement el2);
    
    /**
     * multiply finite field elements
     * @param el1
     * @param el2
     * @return multiple of elements
     */
    public abstract FiniteFieldElement mul(FiniteFieldElement el1, FiniteFieldElement el2);
    
    /**
     * find inverse of element
     * @param el1
     * @return inverse
     */
    public abstract FiniteFieldElement inv(FiniteFieldElement el1);
    
    /**
     * find the rest of element which belongs to the field
     * @param el1
     * @return 
     */
    public abstract FiniteFieldElement mod(FiniteFieldElement el1); 
    
    /**
     * return the element x such that el1 + x = 0 mod order
     * @param el1
     * @return 
     */
    public abstract FiniteFieldElement complement(FiniteFieldElement el1);
    
    /**
     * 
     * @return the field over which this arithmetics is performed
     */
    public FiniteField getField(){
        return field;
    }
    
    /**
     * 
     * @return the factory producing the elements of this field
     */
    public FiniteFieldElementFactory getElementFactory(){
        return elementFactory;
    }
    
    @Override
    public String toString(){
        return "Arithmetics defined over field:"+getField();
    }
    
    /**
     * static factory method to create the arithmetics based on order
     * if fieldOrder instanceof BigInteger -> creates PrimeFieldElementArithmetics
     * if fieldOrder instanceof BinaryExtensionFieldElement -> creates BinaryExtensionFieldElementArithmetics
     * @param fieldOrder
     * @return 
     */
    public static FiniteFieldElementArithmetics createFieldElementArithmetics(BigInteger fieldOrder){
        if(fieldOrder instanceof BinaryExtensionFieldElement) return createFieldElementArithmetics((BinaryExtensionFieldElement)fieldOrder);
        return new PrimeFieldElementArithmetics(new PrimeField(fieldOrder), new FiniteFieldElementFactory());
    }
    
    public static FiniteFieldElementArithmetics createFieldElementArithmetics(BinaryExtensionFieldElement fieldIrreduciblePoly){
        return new BinaryExtensionFieldElementArithmetics(new BinaryExtensionField(fieldIrreduciblePoly), new BinaryExtensionFieldElementFactory());
    }
}
