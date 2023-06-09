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
import java.util.HashSet;
import java.util.Set;

/**
 * Representing polynomial where the bit on position n represents x^n
 */
@SuppressWarnings("serial")
public class BinaryExtensionFieldElement extends FiniteFieldElement{
    
    private int degree;
        
    BinaryExtensionFieldElement(BigInteger element){
        super(element);
    }
    
    /**
     * 
     * @return the degree of this poly
     * example: p = x^5 x^2 1 has degree 5 
     */
    @Override
    public int getDegree() {
        if(this.compareTo(ZERO)==0) return -1;
        
        byte[] array = toByteArray();
        if(degree == 0){
            for(int i = 0; i< array.length;i++){
                for(int j=7; j >= 0; j--){
                    if((array[i]&(1<<j))!=0){
                        degree = 8*(array.length-i-1)+j;
                        return degree;
                    }
                }
            }
        }
        return degree;
    }

    /**
     * 
     * @return the string in format 'x^n x^n-1 ..' 
     */
    @Override
    public String toString(){
        if(this.compareTo(ZERO)==0) return "0";
        
        StringBuilder sb = new StringBuilder();
        byte[] array = toByteArray();
        for(int i = 0; i< array.length;i++){
            for(int j=7; j >= 0; j--){
                if(i==array.length-1&&j==0){
                    if((array[i]&(1<<j))!=0)
                        sb.append("1");
                }else
                    if((array[i]&(1<<j))!=0)
                        sb.append("x^").append(8*(array.length-i-1)+j).append(" ");
            }
        }
        return sb.toString();
    }   
    
    /**
     * create the BinaryExtensionFieldElemen from string notation in format 
     * 'x^n x^n-1 .. x^1 1' 
     * @param notation
     * @return 
     */
    public static BinaryExtensionFieldElement fromString(String notation){
        String[] tokens = notation.split(" ");
        Set<Integer> wasDegree = new HashSet<>();
        BigInteger result = BigInteger.ZERO;
        for(String token: tokens){
            int degree = 0;
            if(token.startsWith("x^")){
                degree = Integer.parseInt(token.substring(2)); 
                if(degree<=0) throw new RuntimeException("unexpected degree");
            } else if(token.equals("1")){
                degree = 0;
            } else{
                throw new RuntimeException("unexpected token");
            }
            if(!wasDegree.contains(degree)){
                wasDegree.add(degree);
                result = result.add(BigInteger.ONE.shiftLeft(degree));
            } else throw new RuntimeException("same degree second time");
        }
        return new BinaryExtensionFieldElement(result);
    }
}
