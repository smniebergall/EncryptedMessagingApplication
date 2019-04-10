package com.example.messagingappencrypted;

import android.util.Pair;

import java.security.Key;
import java.security.KeyPair;
import java.util.Dictionary;
import java.util.Enumeration;

public class User {
    String userID;
    ActualKeyBundle actualBundle;
    Key rootKey;
    Key chainKey;
    Key receivingKey;
    KeyPair sendingKey;
    int messageNumberReceived;
    int messageNumberSent;
    int numberOfMessagesInChain;
    KeyAgreement k;
    Dictionary<Key, String> skippedMessages;//indexed by header key and message number
    //instead of this
    Key headerSending;
    Key headerReceiving;
    Key nextHeaderSending;
    Key nextHeaderReceiving;

    public User(String userID){
        this.userID = userID;
    }

    public void updateKeyBundle(ActualKeyBundle bundle){
        this.actualBundle = bundle;
    }

    public void updateRootAndChainKeys(Key root, Key chain){
        this.rootKey = root;
        this.chainKey = chain;
    }
    //Only if from alice to send message to bob, and doesn't know
    public void updateUserForRatchet(Key secret, Key pub){
        k = new KeyAgreement();
        this.sendingKey = k.generate_DH();
        this.receivingKey = pub;
        KeyPair result = k.DH(this.sendingKey, this.receivingKey);
        Pair<Key, Key> res = k.KDF_RK(secret, result);
        this.rootKey = res.first;
        this.chainKey = res.second;
        this.messageNumberReceived = 0;
        this.messageNumberSent = 0;
        this.numberOfMessagesInChain = 0;
        this.skippedMessages = new Dictionary<Key, String>() {
            @Override
            public int size() {
                return 0;
            }

            @Override
            public boolean isEmpty() {
                return false;
            }

            @Override
            public Enumeration<Key> keys() {
                return null;
            }

            @Override
            public Enumeration<String> elements() {
                return null;
            }

            @Override
            public String get(Object key) {
                return null;
            }

            @Override
            public String put(Key key, String value) {
                return null;
            }

            @Override
            public String remove(Object key) {
                return null;
            }
        };

    }

   /* public Pair ratchetEncrypt(String plainText, String data){
        Pair<Key, Key> p = k.KDF_CK(this.chainKey);
    }*/
}
//double ratchet used to exchange encrypted messages on a shared secret key
//X3DH makes the secret key to exchange messages
//signature schemes
