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

    public KeyBundle getUsersKeyBundle(String otherUserID, String currentUserID){
        KeyBundle bundle = new KeyBundle();
        //get bundle form key distribution center

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
     //dont need this one, have kdf-rk-he
    //do need kdf_ck though
     public Pair<Key, Key> KDF_RK(Key root, Key output){
        Pair<Key, Key> k = null;
        byte[] rootK = root.getEncoded();
        byte[] outputMaterial;
        try{
            Mac mac = Mac.getInstance("SHA256");//change
            byte[] salt = root.getEncoded();
            byte[] info;
            String s = "info for HKDF with Root Key";
            info = s.getBytes(Charset.forName("UTF-8"));
            byte[] outputKey = output.getEncoded();
            HKDFParameters params = new HKDFParameters(outputKey, salt, info);
            HKDFBytesGenerator hkdf = new HKDFBytesGenerator(new SHA256Digest());
            hkdf.init(params);
            byte[] result = new byte[64];
            hkdf.generateBytes(result, 0,64);
            byte[] rootKeyResult = new byte[32];
            byte[] chainKeyResult = new byte[32];
            System.arraycopy(result, 0, rootKeyResult, 0, rootKeyResult.length);
            System.arraycopy(result, 0, chainKeyResult, 0, chainKeyResult.length);
            //Key chain = ;
        }catch(GeneralSecurityException e){

        }

        //regular pair not keypair because pair can do two arrays of bytes
        //(32 root key, 32 chain key);
         //and SHA-256
         //output of applying KDF keyed by a 32 byte root key to a DH output
         //HKDF withh root as salt, output as input key material, and application specific
         //byte sequence as HKDF info. Info should be distinct from others uses of HKDF

         //step 1: extract: PsuedoRandomKey = HMAC-Hash(salt, inputKeyMaterial)
         //step 2: Expand: OuptuKeyMaterial = {N = ceiling(lengthOfOutputInOctets
         //divided by HashLen; T = first L octets of T which are T(0) is empty string
         //and t(1) is HMAC-Hash(PRK, T90) |info | 0x01) and T9@0 is HMAC-Hash(PRK,
         //T(1) | info | 0x02) and so on up to N
         //| means concatenated
         //key.getEncoded() gives byte[] and
         //looks everything is in bte[] instead of keys
        return k;
     }
//java has Signature object with getInstance
    //initSign(PrivateKey private) puts it in sign state
    //initVerify(PubicKey public) puts it in verify state
    //update(byte[] data) or update(byte[] data, int off, int len) to supply to object
    //then sign() and returns byte[]
    //update and verify if in verify state
    //GCMParameterSpec myParams = new GCMParameterSpec(int myTLen, byte[] myIv);
    //Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
    //c.init(Cipher.ENCRYPT_MODE, secretKey, myParams);
    //MAC class (HMACSha256)
    //MessageDIgest sha = MessageDIgest.getInstance("SHA-256");
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
    ///////To implement the DH ratchet, each party generates a DH key pair
    //(a Diffie-Hellman public key and private key) which becomes their current
    // ratchet key pair. Every message from either party begins with a header which
    // contains the sender's current ratchet public key. When a new ratchet public key
    // is received from the remote party, a DH ratchet step is performed which replaces
    // the local party's current ratchet key pair with a new key pair.
    ////////The DH outputs generated during each DH ratchet step are used to derive new
    //sending and receiving chain keys. The below revisits Bob's first ratchet
    //step. Bob uses his first DH output to derive a receiving chain that matches
    //Alice's sending chain. Bob uses the second DH output to derive a new sending chain
    //o a full DH ratchet step consists of updating the root KDF chain twice, and using
    // the KDF output keys as new receiving and sending chain keys
    //When a message is sent or received, a symmetric-key ratchet step is applied to
    //the sending or receiving chain to derive the message key.
    //When a new ratchet public key is received, a DH ratchet step is performed prior
    //to the symmetric-key ratchet to replace the chain keys.
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
             byte[] result = new byte[86];
             hkdf.generateBytes(result, 0,86);
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
             //how to change from byte[] to Key
             //what type of Key??
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
        for(int j = seq.length; j < header.length; j++){
            s[j] = header[j];
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
    //chack with hard coding that encryption and decryption work
    //add errors where appropraite
    //finish look of login and any other activity
    //get rid of spongy castle, only need bouncy castle
    //fix for loops
    //java starts at 0 so need length-1
    //do decrypting and encrypting of header
    //get keys to and from firebase
    //connect to messaging part
}
