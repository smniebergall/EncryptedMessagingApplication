package com.example.messagingappencrypted;

import android.util.Pair;

import java.security.Key;
import java.security.KeyPair;
import java.util.Collection;
import java.util.Dictionary;
import java.util.Enumeration;
import java.util.List;
import java.util.Map;
import java.util.Set;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

public class User {
    String userID;
    ActualKeyBundle actualBundle;
    KeyAgreement k;
    List<State> states;
    public User(String userID){
        this.userID = userID;
        states = null;
    }

    public void addState(State state){
        states.add(state);
    }

    public void deleteState(State state){
        states.remove(state);
    }
    public void updateKeyBundle(ActualKeyBundle bundle){
        this.actualBundle = bundle;
    }

    public void updateRootAndChainKeys(State state, Key root, Key chain){
        state.rootKey = root;
        state.chainKeyReceiving = chain;//right chain key??
    }
    //Only if from alice to send message to bob, and doesn't know
    public void updateUserForRatchet(State state, Key secret, Key pub){
        k = new KeyAgreement();
        state.sendingKey = k.generate_DH();
        state.receivingKey = pub;
        KeyPair result = k.DH(state.sendingKey, state.receivingKey);
        Pair<Key, Key> res = k.KDF_RK(secret, result);
        state.rootKey = res.first;
        state.chainKeySending = res.second;
        state.messageNumberReceived = 0;
        state.messageNumberSent = 0;
        state.numberOfMessagesInChain = 0;
        state.skippedMessages = new Map<Key, Integer>() {
            @Override
            public int size() {
                return 0;
            }

            @Override
            public boolean isEmpty() {
                return false;
            }

            @Override
            public boolean containsKey(@Nullable Object key) {
                return false;
            }

            @Override
            public boolean containsValue(@Nullable Object value) {
                return false;
            }

            @Nullable
            @Override
            public Integer get(@Nullable Object key) {
                return null;
            }

            @Nullable
            @Override
            public Integer put(@NonNull Key key, @NonNull Integer value) {
                return null;
            }

            @Nullable
            @Override
            public Integer remove(@Nullable Object key) {
                return null;
            }

            @Override
            public void putAll(@NonNull Map<? extends Key, ? extends Integer> m) {

            }

            @Override
            public void clear() {

            }

            @NonNull
            @Override
            public Set<Key> keySet() {
                return null;
            }

            @NonNull
            @Override
            public Collection<Integer> values() {
                return null;
            }

            @NonNull
            @Override
            public Set<Entry<Key, Integer>> entrySet() {
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
