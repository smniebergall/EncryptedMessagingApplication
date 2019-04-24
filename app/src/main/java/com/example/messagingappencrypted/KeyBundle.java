package com.example.messagingappencrypted;

import java.security.Key;
import java.security.KeyPair;
import java.util.List;

public class KeyBundle {
    public Key identity;
    public Key prekey;
    public int signature;
    public Key signedPreKey;
    public List<Key> prekeys;

    public KeyBundle(){

    }
    public KeyBundle( Key identity, Key prekey, Key signedPreKey, List<Key> prekeys){
        this.identity = identity;
        this.prekey = prekey;
        this.prekeys = prekeys;
        this.signedPreKey = signedPreKey;
    }

    public void updateBundle(){
        //upsate signature and signed prekey here
    }
}
