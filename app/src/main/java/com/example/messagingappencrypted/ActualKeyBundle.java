package com.example.messagingappencrypted;

import java.security.Key;
import java.security.KeyPair;
import java.util.List;

public class ActualKeyBundle {
    String ID;
    public KeyPair identity;
    public KeyPair prekey;
    public List<KeyPair> prekeys;

    public ActualKeyBundle(){

    }
    public ActualKeyBundle(String ID, KeyPair identity, KeyPair prekey, List<KeyPair> prekeys){
        this.identity = identity;
        this.prekey = prekey;
        this.prekeys = prekeys;
    }
}
