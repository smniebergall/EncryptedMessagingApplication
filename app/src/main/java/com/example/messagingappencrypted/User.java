package com.example.messagingappencrypted;

import android.util.Log;
import android.util.Pair;

import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
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
    KeyAgreement k = new KeyAgreement();
    KeyPair ephemeral;
    List<State> states;
   // private Key ;

    public User(String userID){
        this.userID = userID;
        states = null;
    }
    public KeyPair generateNewEphemeral(){
        KeyPair key = null;
        try{
            KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
            key = generator.generateKeyPair();
        }catch(GeneralSecurityException e){

        }
        ephemeral = key;
        return key;
    }

    public void deleteEphemeralKey(){
        ephemeral = null;
        //put in check for epehemral key being null maybe??

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
    public State findState(State state){

        return states.get(states.indexOf(state));
    }
    public void updateRootAndChainKeys(State state, Key root, Key chain){
        state.rootKey = root;
        state.chainKeyReceiving = chain;//right chain key??
    }

    //Only if from alice to send message to bob, and doesn't know
    public void updateUserForRatchetStart(State state, Key secret, Key pub, Key sharedHeaderKeySelf, Key sharedNextHeaderOther){
        k = new KeyAgreement();
        state.sendingKey = k.generate_DH();
        state.receivingKey = pub;
        Key result= k.DH(state.sendingKey, state.receivingKey);
        Pair<Pair<Key, Key>, Key> res = k.kdf_rk_he(state, secret, result);
        //change KDF_RK second argument to regular key?
        state.rootKey = res.first.first;
        state.chainKeySending = res.first.second;
        state.nextHeaderSending = res.second;
        state.chainKeyReceiving = null;
        state.messageNumberReceived = 0;
        state.messageNumberSent = 0;
        state.numberOfMessagesInChain = 0;
        state.headerSending = sharedHeaderKeySelf;
        state.headerReceiving = null;
        state.nextHeaderReceiving = sharedNextHeaderOther;
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

    public void updateUserFOrRatchetSecond(State state, Key secret, KeyPair priv, Key sharedHeaderKeyOther, Key nextHeaderSelf){
        state.sendingKey = priv;
        state.receivingKey = null;
        state.rootKey = secret;
        state.chainKeySending = null;
        state.chainKeyReceiving = null;
        state.messageNumberSent = 0;
        state.messageNumberReceived = 0;
        state.numberOfMessagesInChain = 0;
        state.headerSending = null;
        state.nextHeaderSending = nextHeaderSelf;
        state.headerReceiving = null;
        state.nextHeaderReceiving = sharedHeaderKeyOther;
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

    public String encrypt(State state, String message, String data){
        Pair<Header, byte[]> p = k.ratchetEncrypt(state, message, data.getBytes());//what is data?? random?
        String ciphertext = p.second.toString();
        return ciphertext;
    }

    public String decrypt(State state, String message, String data){
        //state, header ib bytes, message in bytes, abd data in bytes
        //
        byte[] header = null;//get from message, first 40 i think??
        byte[] messageText = message.getBytes();
        byte[] actualMessage = null;
        for(int i =0; i < messageText.length; i++){
            if(i < 40){
                header[i] = messageText[i];
            }
            else{
                actualMessage[i] = messageText[i];
            }
        }
        byte[] plain = k.ratchetDecrypt(state, header, actualMessage, data.getBytes());
        return  plain.toString();
    }

    public Key calculateSecretKey(Key IdentityOtherPub, Key SignedPreKeyOtherPub, byte[] signatureOfPreKeyOtherPub, Key oneTimePreKeyOtherpub){
        Log.i("IDK", "In users calculate secret key");
        Log.i("IDK", "In users calculate secret key, identity: " );
        //bundle2.identity, bundle2.signedPreKey, bundle2.signedPreKeyBytes, bundle2.pickPrekeyToSend()
        Key secret = k.calculateSecretKey(this, IdentityOtherPub, SignedPreKeyOtherPub, signatureOfPreKeyOtherPub, oneTimePreKeyOtherpub);
        Log.i("IDK", "Finished users calculate secret key");
        if(secret == null){
            Log.i("IDK", "Secret is null");//secret is defitnely null
        }
        Log.i("IDK", "In users calculate secret key, secret key length " + secret.getEncoded().length);//says this secret is null
        return secret;
    }

    public byte[] encryptInitialMessage(Key key, byte[] text, byte[] AD){
        byte[] ciphertext = k.encrypt(key, text, AD);
        return ciphertext;
    }

    public byte[] decryptInitialMessage(Key key, byte[] ciphertext, byte[] AD){
        byte[] plaintext = k.decrypt(key, ciphertext, AD);
        return plaintext;
    }

    public byte[] signPreKey(KeyPair identity, byte[] bytes){
        //null object reference down 1
        byte[] result = new byte[32];
        Log.i("IDK", "User sign identity pub: " + identity.getPublic());
        Log.i("IDK", "User sign identity priv: " + identity.getPrivate());
        Log.i("IDK", "User sign bytes: " + bytes);
        Log.i("IDK", "User sign bytes length: " + bytes.length);
        try {
            result = k.sig(identity, bytes);//definitely erroring here!!!!
        }catch(Exception e) {
            Log.i("IDKERROR", e.toString());
        }
        Log.i("IDK", "User sign result: " + result);
        Log.i("IDK", "User sign result length: " + result.length);
        return result;
    }
    //initialize using updateUserForRatchet#, after secret key is is agreed on
    //Alice's first message encrypted using ratchetEncrypt(state, string text, byte[])
    //and sent to bob
    //who does ratchet decrypt

}
//double ratchet used to exchange encrypted messages on a shared secret key
//X3DH makes the secret key to exchange messages
//signature schemes
