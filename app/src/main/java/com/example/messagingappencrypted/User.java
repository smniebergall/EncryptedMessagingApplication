package com.example.messagingappencrypted;

import java.security.Key;

public class User {
    public String userID;
    public ActualKeyBundle actualBundle;
    public Key rootKey;
    public Key chainKey;
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
}
