package com.example.messagingappencrypted;

import java.security.Key;
import java.security.KeyPair;
import java.util.ArrayList;
import java.util.List;

public class KeyBundle {
    public Key identity;
    public Key prekey;
    public int signature;
    public Key signedPreKey;
    public byte[] signedPreKeyBytes;
    public List<Key> prekeys;
    //public ArrayList<Key> prekeys;

    public KeyBundle(){

    }
    public KeyBundle( Key identity, Key prekey, Key signedPreKey, ArrayList<Key> prekeys){
        this.identity = identity;
        this.prekey = prekey;
        this.prekeys = prekeys;
        this.signedPreKey = signedPreKey;
    }

    public void updateBundle(){
        //upsate signature and signed prekey here
    }
    public Key pickPrekeyToSend(){
        Key prekey = null;
        if(prekeys != null){
            prekey = prekeys.get(0);
            //prekeys.remove(prekey);
            //uncoment above for real thingy
            //and add in chekcs to see if you need to create more
            //one-time keys to update in firebase also
            //now update in firebase!

        }

        return prekey;
    }
    public Key getSpecificPreKey(int i){
        return prekeys.get(i);
    }
    public Key getSignedPreKey(){
        return signedPreKey;
    }
}
