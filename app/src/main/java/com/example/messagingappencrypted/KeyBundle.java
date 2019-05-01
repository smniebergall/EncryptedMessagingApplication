package com.example.messagingappencrypted;

import android.util.Log;

import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.List;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

public class KeyBundle {
    public Key identity;
    public Key prekey;
    public int signature;
    public SecretKey signedPreKey = null;
    public byte[] signedPreKeyBytes;
    public List<Key> prekeys;
    //public ArrayList<Key> prekeys;

    public KeyBundle(){

    }
    public KeyBundle( Key identity, Key prekey, byte[] signedPreKey, List<Key> prekeys){
        this.identity = identity;
        this.prekey = prekey;
        this.prekeys = prekeys;
        if(signedPreKey == null){
            Log.i("IDK", "signedPrekey is null");
        }
        Log.i("IDK", "signedPrekey: " + signedPreKey.toString());
        try{
            this.signedPreKey = new SecretKeySpec(signedPreKey, 0, signedPreKey.length, "AES");//why is this an empty key??
            Log.i("IDK", "this.signedPrekey: " + this.signedPreKey.toString());

        }catch(Exception e){
            Log.i("IDKERROR2", e.toString());
        }

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
