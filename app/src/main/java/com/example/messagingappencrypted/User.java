package com.example.messagingappencrypted;

import android.util.Pair;

import java.security.Key;
import java.security.KeyPair;
import java.util.Collection;
import java.util.Dictionary;
import java.util.Enumeration;
import java.util.Iterator;
import java.util.List;
import java.util.ListIterator;
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
        Key result = k.DH(state.sendingKey, state.receivingKey);
        Pair<Key, Key> res = k.KDF_RK(secret, result);
        //change KDF_RK second argument to regular key?
        state.rootKey = res.first;
        state.chainKeySending = res.second;
        state.messageNumberReceived = 0;
        state.messageNumberSent = 0;
        state.numberOfMessagesInChain = 0;
        state.skippedMessages = new Map<Pair<Key, Integer>, Key>() {
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
            public Key get(@Nullable Object key) {
                return null;
            }

            @Nullable
            @Override
            public Key put(@NonNull Pair<Key, Integer> key, @NonNull Key value) {
                return null;
            }

            @Nullable
            @Override
            public Key remove(@Nullable Object key) {
                return null;
            }

            @Override
            public void putAll(@NonNull Map<? extends Pair<Key, Integer>, ? extends Key> m) {

            }

            @Override
            public void clear() {

            }

            @NonNull
            @Override
            public Set<Pair<Key, Integer>> keySet() {
                return null;
            }

            @NonNull
            @Override
            public Collection<Key> values() {
                return null;
            }

            @NonNull
            @Override
            public Set<Entry<Pair<Key, Integer>, Key>> entrySet() {
                return null;
            }
        };
    }

}
//double ratchet used to exchange encrypted messages on a shared secret key
//X3DH makes the secret key to exchange messages
//signature schemes
