package com.example.messagingappencrypted;

import android.util.Pair;

import java.security.Key;
import java.security.KeyPair;
import java.util.Dictionary;
import java.util.List;
import java.util.Map;

public class State {
    String ID;
    Key headerSending;
    Key headerReceiving;
    Key nextHeaderSending;
    Key nextHeaderReceiving;
    Key rootKey;
    Key chainKeySending;
    Key chainKeyReceiving;
    Key receivingKey;
    KeyPair sendingKey;
    int messageNumberReceived;
    int messageNumberSent;
    int numberOfMessagesInChain;
    Map<Pair<Key, Integer>, Key> skippedMessages;//indexed by header key and message number
    //instead of this
    public State(){

    }
}
