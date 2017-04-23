/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package RSApp;

import java.io.Serializable;

/**
 *
 * @author Mauricio
 */
public class Message implements Serializable {
    private byte[] message;
    private byte[] sign;
    private String type;

    public Message(byte[] message, byte[] sign, String type) {
        this.message = message;
        this.sign = sign;
        this.type = type;
    }

    
    public byte[] getMessage() {
        return message;
    }

    public byte[] getSign() {
        return sign;
    }

    public String getType() {
        return type;
    }
    
    
    
}
