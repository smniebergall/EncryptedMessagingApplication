package com.example.messagingappencrypted;

import android.security.keystore.KeyGenParameterSpec;
import android.util.Pair;

import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.security.KeyPair;
import java.security.Signature;
import java.security.*;
import java.security.spec.KeySpec;
import java.util.Enumeration;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import org.bouncycastle.*;
import org.spongycastle.crypto.Digest;
import org.spongycastle.crypto.digests.SHA256Digest;
import org.spongycastle.crypto.generators.HKDFBytesGenerator;
import org.spongycastle.crypto.params.HKDFParameters;

import javax.crypto.Cipher;
import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import co.chatsdk.core.types.KeyValue;

public class KeyAgreement {
    int max_skip = 7;//what is good max skip amount??

    public KeyAgreement(){

    }
    public byte[] encode(Key pub){
        return pub.getEncoded();
        //pub.g
        //The recommended encoding consists of some single-byte constant
        // to represent the type of curve, followed by little-endian encoding
        // of the u-coordinate as specified in [1].
    }
    //DH(PK1, PK2) represents a byte sequence which is the shared secret output
    // from an Elliptic Curve Diffie-Hellman function involving the key pairs
    // represented by public keys PK1 and PK2.

    //Sig(PK, M) represents a byte sequence that is an XEdDSA signature on the byte
    // sequence M and verifies with public key PK, and which was created by signing
    // M with PK's corresponding private key. The signing and verification functions
    // for XEdDSA are specified in[2].

    //for kdf, should i bed doing multiple kdfs?? or do the output of 80
    //and chop into keys??

    //IKA alices identity
    //EKA alices ephemeralkey
    //IKB bobs identity
    //SPKB bobs signed prekey
    //OPKB bobs one time prekey
    //all keys must be within x25519 for this protocol X3DH

    //Each party has a long-term identity public key (IKA for Alice, IKB for Bob).
    //Bob also has a signed prekey SPKB, which he will change periodically, and a
    // set of one-time prekeys OPKB, which are each used in a single X3DH protocol
    //run. ("Prekeys" are so named because they are essentially protocol messages
    // which Bob publishes to the server prior to Alice beginning the protocol run).
    //During each protocol run, Alice generates a new ephemeral key pair with public
    // key EKA.
    //After a successful protocol run Alice and Bob will share a 32-byte secret key
    // SK.

    //Step 1: Alice gets prekey bundle from server. Serve gives one of the one-time
    //prekeys and then deletes it. If there isnt one, no one time prekey is given
    //ALice verifies prekey signature and if it works then creates EKA key pair
    //if no one-time prekey:
    //DH1 = DH(IKA, SPKB); DH2 = DH(EKA, IKB); DH3 = DH(EKA, SPKB);
    //SK = KDF(DH1 || DH2 || DH3)
    //if there is a prekey:
    //add additional DH4 = DH(EKA, OPKB); SK includes DH4 at end
    //then ephemeral private key for Alice is deleted and DH outputs.

    //alice creates associated data byte sequence AD=encode(IKA) || encode(IKB)
    //Step 2: alice sends Bob message containing A's IKA, EKA, identifiers saying
    //which B's prekeys ALice used, an initial encrypted ciphertext using AEAD
    //encryption scheme using AD and encryption key of either SK or output
    //from some cryptographic PRF keyed by SK

    //A can continue using SK or keys derived from SK to communicate
    public Key calculateSecretKey(User user, Key IKO, Key SPKO, byte[] signedPrekeyO, Key OPKO){
        //verify prekeysignature
        //then generate ephemeral here if verified
        //otherwise abort
        user.generateNewEphemeral();
        Key dh1 = DH(user.actualBundle.identity, SPKO);
        Key dh2 = DH(user.ephemeral, IKO);

        Key secret;
        Key dh3 = DH(user.ephemeral, SPKO);
        //maybe not current users prekey, make a new ephemeral key for this
        if(OPKO != null){
            Key dh4 = DH(user.ephemeral, OPKO);//maybe change ephemeral to actual key bundle??
            byte[] concated = concat(concat(concat(dh1.getEncoded(), dh2.getEncoded()), dh3.getEncoded()), dh4.getEncoded());
            secret = KDF(concated);
        }
        else
        {
            byte[] concated = concat(concat(dh1.getEncoded(), dh2.getEncoded()), dh3.getEncoded());
            secret = KDF(concated);
        }

        return secret;
    }
    public byte[] initialMessage(Key IKA, Key IKB, Key EKA, int[] identifiers, byte[] ciphertext){
        byte[] bytes = null;
        bytes = concat(concat(concat(IKA.getEncoded(), EKA.getEncoded()), ByteBuffer.allocate(1).putInt(identifiers[0]).array()), ciphertext);
        return bytes;
    }
    public Key KDF(byte[] seq){
        byte[] result = new byte[32];
        //32 byte output from HKDF with inputs:
        //input key material is F || seq where f id bte seq containing
        //32 0xFF bytes
        byte[] bytes = new byte[32];
        byte[] input = new byte[bytes.length+seq.length];
        for(int i = 0; i < bytes.length; i++){
            bytes[i] = (byte)0xFF;
        }
        input = concat(bytes, seq);
        byte[] salt = new byte[32];//hash output length?? I think 32 because binary
        String infoString = "Info for KDF for key agreement";
        byte[] info = infoString.getBytes();
        HKDFParameters params = new HKDFParameters(input, salt, info);
        HKDFBytesGenerator hkdf = new HKDFBytesGenerator(new SHA256Digest());
        hkdf.init(params);
        hkdf.generateBytes(result, 0,32);

        //change any loops with sequences to concat,
        //and probably change concat itself

        //salt is zero filled byte sequence equal to hash output length
        //info = "KDF for X3DH"
        SecretKey k = new SecretKeySpec(result, "AES");
        return k;
    }

    //probbaly only need to do new type of conversation not new type of message
    //should I do immediate decrypt on receiving message or have button
    //button seems like a good idea

//Alice verifies the prekey signature and aborts the protocol if verification fails.
// Alice then generates an ephemeral key pair with public key EKA.
//After calculating SK, Alice deletes her ephemeral private key and the DH outputs.
//Alice then calculates an "associated data" byte sequence AD that contains identity
// information for both parties:
//    AD = Encode(IKA) || Encode(IKB)
    //Alice then sends Bob an initial message containing: Alice's identity key IKA,
    //Alice's ephemeral key EKA, Identifiers stating which of Bob's prekeys Alice used,
    //An initial ciphertext encrypted with some AEAD encryption scheme [4] using AD
// as associated data and using an encryption key which is either SK or the output
// from some cryptographic PRF keyed by SK.

    //The initial ciphertext is typically the first message in some post-X3DH
    // communication protocol. In other words, this ciphertext typically has two
    // roles, serving as the first message within some post-X3DH protocol, and as
    // part of Alice's X3DH initial message.
    public byte[] sig(KeyPair pair, byte[] message){
        byte[] bytes = null;
        //maybe 25519 for signature??
        try{
            Signature signature = new Signature("Ed25519") {
                @Override
                protected void engineInitVerify(PublicKey publicKey) throws InvalidKeyException {

                }

                @Override
                protected void engineInitSign(PrivateKey privateKey) throws InvalidKeyException {

                }

                @Override
                protected void engineUpdate(byte b) throws SignatureException {

                }

                @Override
                protected void engineUpdate(byte[] b, int off, int len) throws SignatureException {

                }

                @Override
                protected byte[] engineSign() throws SignatureException {
                    return new byte[0];
                }

                @Override
                protected boolean engineVerify(byte[] sigBytes) throws SignatureException {
                    return false;
                }

                @Override
                protected void engineSetParameter(String param, Object value) throws InvalidParameterException {

                }

                @Override
                protected Object engineGetParameter(String param) throws InvalidParameterException {
                    return null;
                }
            };
            signature.initSign(pair.getPrivate());
            signature.update(message);
            bytes = signature.sign();
            //just sign and verify??
        }catch(GeneralSecurityException e){

        }

        //represents a byte sequence that is an XEdDSA signature on the byte sequence
        // M and verifies with public key PK, and which was created by signing M with
        // PK's corresponding private key. The signing and verification functions for
        // XEdDSA are specified in[2].
        return bytes;
    }
    public KeyBundle getUsersKeyBundle(String otherUserID, String currentUserID){
        KeyBundle bundle = new KeyBundle();
        //get bundle form key distribution center
        Key IKO;
        Key SPKO;
        Key signedPrekeyO;
        Key OPKO;
        //only use 1 one-time prekey and delete it from firebase
        return bundle;
    }
    public KeyPair generate_DH(){
        KeyPair k = null;
        try{
            KeyPairGenerator generator = KeyPairGenerator.getInstance("X25519");
            k = generator.generateKeyPair();
            //java says this exists, android developers says it doesn't?
            //share key with server (String)(Base65.encode(pubKeu.encoded, 0)) maybe?
            //maybe with spongy castle?
        }catch(GeneralSecurityException e){
            //handle exception here
        }
        return k;
    }

     public Key DH(KeyPair pair, Key pub){
        //DH calculation using pair private key and public
         //byte[] bytes = null;
         Key a = null;
         try{
             javax.crypto.KeyAgreement agree = javax.crypto.KeyAgreement.getInstance("DH");
             agree.init(pair.getPrivate());
             a = agree.doPhase(pub, true);
             //bytes = agree.generateSecret();
         }catch(GeneralSecurityException e){
             //handle exception here
         }
         //return bytes;
         return a;
     }

     public Pair<Key, Key> KDF_CK(Key chain){
        Pair<Key, Key> k = null;
        //need to turn string chain key into speicific kind of key like SecretKeySpec
         //new SecretKeySPec(key.getBytes("UTF-8"), "AES") for example
         //so elliptic version?
         //byte[] chains =
         try{
             //HMAC SHA256
             //chain key as HMAC key and separate input
             //0x01 for message key and 0x02 for next chian key
             Mac HMAC_SHA256 = Mac.getInstance("HmacSHA256");
             HMAC_SHA256.init(chain);
             byte[] messageKey;
             byte[] nextChainKey;
             //byte[] bytes = {"0x01"., "0x02"};
             byte[] one = new byte[1];
             one[0] = (byte)0x01;
             byte[] two = new byte[1];
             two[0] = (byte)0x02;
             messageKey = HMAC_SHA256.doFinal(one);
             nextChainKey = HMAC_SHA256.doFinal(two);
             SecretKey mkey = new SecretKeySpec(messageKey, "AES");
             SecretKey ckey = new SecretKeySpec(nextChainKey, "AES");
             k = new Pair(mkey, ckey);

         }catch(GeneralSecurityException e){

         }

         //Mac mac = Mac.getInstance("HmacSHA1");
        //wrap and unwrap keys when sending them
        //(32-byte chain key, 32-byte message key);
         //applying KDF keyed by a 32 byte chian key to come constant
         //HMAC, chain key as HMAC key and using separate constants as input
         //like 0x01 as input to produce message key,a nd 0x02 to produce
         //next chain key
        return k;
     }

     public byte[] encrypt(Key messageKey, byte[] plainText, byte[] data){
         byte[] bytes = null;
         try{
             //spongy castle does HKDF
            byte[] salt = new byte[80];
            byte[] info;
            String s = "info for HKDF";
            info = s.getBytes(Charset.forName("UTF-8"));
            byte[] messagekey = messageKey.getEncoded();
            HKDFParameters params = new HKDFParameters(messagekey, salt, info);
            HKDFBytesGenerator hkdf = new HKDFBytesGenerator(new SHA256Digest());
            hkdf.init(params);
            byte[] result = new byte[80];
            hkdf.generateBytes(result, 0,80);
            byte[] encryptionKey = new byte[32];
            byte[] authKey = new byte[32];
            byte[] IV = new byte[16];//is this correct order?
            for(int i = 0; i < 31; i++){
                encryptionKey[i] = result[i];//fix the arrays 0-32, 32-64, 64-80
            }
            for(int i = 32; i < 63; i++){
                authKey[i] = result[i];
            }
            for(int i = 64; i < result.length-1; i++){
                IV[i] = result[i];
            }
             Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");//change to PCKS7Padding
             //from bouncy castle??
             IvParameterSpec iv = new IvParameterSpec(IV);
             SecretKeySpec encKey = new SecretKeySpec(encryptionKey, "HMAC_SHA256");
             SecretKeySpec aKey = new SecretKeySpec(authKey, "HMAC_SHA256");//Is this right??
             cipher.init(Cipher.ENCRYPT_MODE, encKey, iv);
             byte[] encrypted = cipher.doFinal(plainText);
             Mac mac = Mac.getInstance("HmacSHA256");
             mac.init(aKey);
             byte[] hmac = mac.doFinal(concat(data, encrypted));
             bytes = new byte[hmac.length+encrypted.length];
             System.arraycopy(encrypted, 0, bytes, 0, encrypted.length);
             System.arraycopy(hmac, 0, bytes, encrypted.length, hmac.length);
         }catch(GeneralSecurityException e){

         }
        return bytes;
     }

     public byte[] decrypt(Key messageKey, byte[] cipherText, byte[] data){
        byte[] bytes = null;
        SecureRandom s = new SecureRandom();
        IvParameterSpec IV;
        byte[] ivBytes = new byte[16];
        s.nextBytes(ivBytes);
        IV = new IvParameterSpec(ivBytes);
        try{
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.DECRYPT_MODE, messageKey, IV);
            byte[] decrypted = cipher.doFinal(cipherText);
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(messageKey);
            byte[] hmac = mac.doFinal(concat(data, decrypted));
            bytes = new byte[hmac.length+decrypted.length];
            System.arraycopy(decrypted, 0, bytes, 0, decrypted.length);
            System.arraycopy(hmac, 0, bytes, decrypted.length, hmac.length);
            //if authentictaion fails, exception is raised
            //but what is associated data and hwo does authentication fail
            //it has to match something right?? what??
        }catch(GeneralSecurityException e){

        }
        return bytes;
     }

     public byte[] header(KeyPair dhPair, int chainLength, int messageNumber){
        byte[] bytes = new byte[40];
        byte[] n;
        byte[] pmic;
        byte[] dh;
        n = ByteBuffer.allocate(4).putInt(messageNumber).array();
        pmic = ByteBuffer.allocate(4).putInt(chainLength).array();
        dh = dhPair.getPublic().getEncoded();
        for(int i = 0; i < bytes.length; i++){
            if(i < 4){
                bytes[i] = n[i];
            }
            else if(i < 8){
                bytes[i] = pmic[i];
            }
            else {
                bytes[i] = dh[i];
            }
        }
        //yes use public key
         //edDSA based on shnorr
        //create new message header containing DH ratchet public key from the key pair
         //Header Object?
        return bytes;
     }

     public byte[] hencrypt(Key headerKey, byte[] plainText){
        byte[] bytes = null;
         SecureRandom s = new SecureRandom();
         IvParameterSpec IV;
         byte[] ivBytes = new byte[16];
         s.nextBytes(ivBytes);
         IV = new IvParameterSpec(ivBytes);
        try{
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, headerKey, IV);
            bytes = cipher.doFinal(plainText);
        }catch(GeneralSecurityException e){

        }
        //AEAD encryption of plaintext with header key
         //nonce must be either non-repeating or ranodm non-repeating chosen with
         //128 bits of entropy
        return bytes;
     }

     public Header hdecrypt(Key headerKey, byte[] plaintext){
         if(headerKey == null){
             return null;
         }
         Header header = new Header();
         SecureRandom s = new SecureRandom();
         IvParameterSpec IV;
         byte[] bytes = null;
         byte[] ivBytes = new byte[16];
         s.nextBytes(ivBytes);
         IV = new IvParameterSpec(ivBytes);
        try{
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.DECRYPT_MODE, headerKey, IV);
            bytes = cipher.doFinal(plaintext);
            //first 4 bytes are integer n
            //next 4 bytes is number of messages in previous chain
            //and next 32 bytes are the key
            byte[] n = new byte[4];
            byte[] pmic = new byte[4];
            byte[] k = new byte[32];
            for(int i = 0; i < bytes.length; i++){
                if(i < 4){
                    n[i] = bytes[i];
                }
                else if(i < 8){
                    pmic[i] = bytes[i];
                }
                else{
                    k[i] = bytes[i];
                }
            }
            SecretKey dh = new SecretKeySpec(k, "AES");
            header.updateHedaer(new BigInteger(n).intValue(), new BigInteger(pmic).intValue(), dh);
        }catch(GeneralSecurityException e){

        }
        //AEAD, if authentication fails or headerKey is empty, return NONE
        return header;
     }
    //To allow Bob and ALice to send messages immediately after initialization Bob's
    // sending chain key and Alice's receiving chain key could be initialized to a
    // shared secret.
     public Pair<Pair<Key, Key>, Key> kdf_rk_he(State state, Key root, Key output){
         //returns new root key, chain key, and next header key as output of applying
         //KDF keyed by root key to DH output
         //how to return all three??
         //probbaly still EC DH key??
         Pair<Pair<Key, Key>, Key> keys = null;
         try{
             byte[] info;
             String s = "HKDF for lots of keys";
             info = s.getBytes(Charset.forName("UTF-8"));
             HKDFParameters params = new HKDFParameters(root.getEncoded(), output.getEncoded(), info);
             HKDFBytesGenerator hkdf = new HKDFBytesGenerator(new SHA256Digest());
             hkdf.init(params);
             byte[] result = new byte[96];
             hkdf.generateBytes(result, 0,96);
             //does this create one key? multiple keys??
             byte[] rootKeyResult = new byte[32];
             byte[] chainKeyResult = new byte[32];
             byte[] nextHeaderKey = new byte[32];
             System.arraycopy(result, 0, rootKeyResult, 0, rootKeyResult.length);
             System.arraycopy(result, rootKeyResult.length, chainKeyResult, 0, chainKeyResult.length);
             System.arraycopy(result, chainKeyResult.length, nextHeaderKey, 0, nextHeaderKey.length);
             KeyFactory kf = KeyFactory.getInstance("EC");//may not need this
             SecretKey rkey = new SecretKeySpec(rootKeyResult,  "AES");//AES is 32-byte i think
             SecretKey ckey = new SecretKeySpec(chainKeyResult,  "AES");
             SecretKey nkey = new SecretKeySpec(nextHeaderKey, "AES");
             keys = new Pair(new Pair(rkey, ckey), nkey);
             //256 bits key is 32-byte array
         }catch(GeneralSecurityException e){

         }
         //Pair<Pair<RootKey, ChainKey>, nextHeaderKey>
         return keys;
     }
     public byte[] concat(byte[] seq, byte[] header){
        byte[] s = new byte[header.length+seq.length];
        for(int i = 0; i < seq.length; i++){
            s[i] = seq[i];

        }
        for(int j = seq.length; j < header.length+seq.length; j++){
            s[j] = header[j-header.length];
        }
        return s;
     }
    //to retrieve info from firebase...
    //private DatabadReference database;
    //database = FirebaseDatabase.getInstance().getReference();
    //can update database.child("users").child(userId).child("username").setValue(name);
    //ValueEventListener postListener = new ValueEventListener(){
    //@Override
    //public void onDataChange(DataSnapshot dataSnapshot){
    //Class class = dataSnapshot.getValue(Class.class);}
    //@override
    //public void onCancelled(DatabaseError databaseError){
    //Log.w(TAG, "loadPost:onCancelled", databaseError.toException());}
    //TO retrieve data, use Query q =...
    public Pair ratchetEncrypt(State state, String plainText, byte[] associatedData){
        Key messageKey;
        Pair<Header, byte[]> k;//header key or string? byte[]??
        Pair<Key, Key> pair = KDF_CK(state.chainKeyReceiving);
        state.chainKeyReceiving = pair.second;
        messageKey = pair.first;
        byte[] bytesPlainText = plainText.getBytes(Charset.forName("UTF-8"));
        byte[] header = header(state.sendingKey, state.numberOfMessagesInChain, state.messageNumberSent);
        byte[] encryptedHeader = hencrypt(state.nextHeaderSending, header);
        state.messageNumberSent++;
        k = new Pair(header, encrypt(messageKey, bytesPlainText, concat(associatedData, encryptedHeader)));
        return k;
    }

    public byte[] ratchetDecrypt(State state, byte[] h, byte[] cipherText, byte[] associated){
        Header header;
        byte[] plainText = TrySkippedMessageKeys(state, h, cipherText, associated);
        if(plainText != null){
            return plainText;
        }
        Pair<Header, Boolean> p = decryptHeader(state, h);
        header = p.first;
        if(p.second){
            SkipMessageKeys(state, header.numberOfMessagesInPreviousChain);
            DHRatchet(state, header);
        }
        SkipMessageKeys(state, header.n);
        Pair<Key, Key> pair = KDF_CK(state.chainKeyReceiving);
        state.chainKeyReceiving = pair.second;
        Key messageKey = pair.first;
        state.messageNumberReceived++;
        return decrypt(messageKey, cipherText, concat(associated, h));
    }

    public byte[] TrySkippedMessageKeys(State state, byte[] h, byte[] cipherText, byte[] AD){
        Header header;
        Key messageKey;
        for(Iterator<Map.Entry<Pair<Key, Integer>, Key>> entries = state.skippedMessages.entrySet().iterator(); entries.hasNext();){
            Map.Entry<Pair<Key, Integer>, Key> entry = entries.next();
            header = hdecrypt(entry.getKey().first, h);
            if(header != null && header.n == entry.getKey().second){
                messageKey = entry.getValue();
                state.skippedMessages.remove(entry.getKey());
                return decrypt(messageKey, cipherText, concat(AD, h));
            }
        }
        return null;
    }

    public Pair<Header, Boolean> decryptHeader(State state, byte[] encryptedHeader){
        Pair<Header, Boolean> p;
        Header header = hdecrypt(state.headerReceiving, encryptedHeader);
        if(header != null){
            p = new Pair(header, false);
            return p;
        }
        header = hdecrypt(state.nextHeaderReceiving, encryptedHeader);
        if(header != null){
            p = new Pair(header, true);
            return p;
        }
        else { return null;//
        }
    }

    public void SkipMessageKeys(State state, int until){
        if (state.messageNumberReceived + max_skip < until){
            //raise Error()
        }
        if (state.chainKeyReceiving != null)
                while (state.messageNumberReceived < until){
                    Pair<Key, Key> receivingMessagePair = KDF_CK(state.chainKeyReceiving);
                    state.chainKeyReceiving = receivingMessagePair.first;
                    Key messageKey = receivingMessagePair.second;
                    Pair<Key, Integer> p = new Pair(state.headerReceiving, state.messageNumberReceived);
                    state.skippedMessages.put(p, messageKey);
                    state.messageNumberReceived++;
                }

    }
    public void DHRatchet(State state, Header header){
            state.numberOfMessagesInChain = state.messageNumberSent;
            state.messageNumberSent = 0;
            state.messageNumberReceived = 0;
            state.headerSending = state.nextHeaderSending;
            state.headerReceiving = state.nextHeaderReceiving;
            state.receivingKey = header.dh;
            Pair<Pair<Key, Key>, Key> pair;
            pair = kdf_rk_he(state, state.rootKey, DH(state.sendingKey, state.receivingKey));
            state.rootKey = pair.first.first;
            state.chainKeyReceiving = pair.first.second;
            state.nextHeaderReceiving = pair.second;
            state.sendingKey = generate_DH();
            Pair<Pair<Key, Key>, Key> rootSendingPair = kdf_rk_he(state, state.rootKey, DH(state.sendingKey, state.receivingKey));
            state.rootKey = rootSendingPair.first.first;
            state.chainKeySending = rootSendingPair.first.second;
            state.nextHeaderSending = rootSendingPair.second;
    }
    //DH Ratchet:
    //each party generates dh key pair that becomes their current ratchet key pair
    //every messages from either party has a header which contains the senders
    //current ratchet public key
    //when new public key received, dh ratchet step is performed,
    //which replaces the local party's current ratchet key pair with a new pair


    //TO DO
    //finish X3DH signatures with elliptic curves
    //put into actual messages to display
    //tests for secret key agreement, firebase publish and get and update keys,
    //chack with hard coding that encryption and decryption work
    //add errors where appropriate
    //finish look of login and any other activity
    //get rid of spongy castle, only need bouncy castle
    //fix for loops
    //java starts at 0 so need length-1
    //do decrypting and encrypting of header
    //get keys to and from firebase
    //connect to messaging part
    //fix concat and change anything other loops to concat
    //finish  XEDDSA and VXEDDSA signature schemes
}
