package com.example.messagingappencrypted;

import java.security.Key;
import java.security.KeyPair;

public class Header {
    Key dh;
    int numberOfMessagesInPreviousChain;
    Integer n;

    public Header(){

    }

    public void updateHedaer(int n, int pmic, Key k){
        this.n = n;
        this.numberOfMessagesInPreviousChain = pmic;
        this.dh = k;
    }
}
