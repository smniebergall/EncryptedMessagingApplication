package com.example.messagingappencrypted;

import android.security.keystore.KeyGenParameterSpec;
import android.util.Pair;

import java.security.Key;
import java.security.KeyPair;
import java.security.Signature;
import java.security.*;
import java.util.Enumeration;

import javax.crypto.Cipher;
import javax.crypto.*;

import co.chatsdk.core.types.KeyValue;

public class KeyAgreement {
    int max_skip = 5;//what is good max skip amount??
    public KeyAgreement(){

    }
    //DH(PK1,PK2): byte sequence which is shared secret
    //SIg(PK, M): byte sequence that is XEdDSA signature on the byte sequence
    //M and verifies with PK, which was created by signing M with PK's
    //corresponding private key.
    //KDF(KM): 32 bytes of output from the HKDF algorithm with inputs:
    //key- F concat KM, where KM is input byte seqeunce containign secret key
    //material and F is byte sequence of either 32 0xFF bytes if X25519
    //or 57 0xFF bytes if X448
    //salt- a zero filled byte sequence with equal length to the hash output len
    //info - info parameter above
    //IKA is A's identity key, IKB is B's identity, EKA is A's medium key
    //SPKB is B's signed prekey, OPKB is B's one time prekey
    //
    //Step 1: Alice gets prekey bundle from server. Serve gives one of the one-time
    //prekeys and then deletes it. If there isnt onw, no one time prekey is given
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
            KeyPairGenerator generator = KeyPairGenerator.getInstance("X25519", "SC");
            k = generator.generateKeyPair();
            //java says this exists, android developers says it doesn't?
            //share key with server (String)(Base65.encode(pubKeu.encoded, 0)) maybe?
            //maybe with spongy castle?
        }catch(GeneralSecurityException e){
            //handle exception here
        }
        return k;
    }

     public KeyPair DH(KeyPair pair, Key pub){
        //DH calculation using pair private key and pub
         //if invalid public keys, exception
         /*byte[] b = new byte[256];
         return b;*/
         KeyPair k = null;
         try{
             KeyPairGenerator generator = KeyPairGenerator.getInstance("X25519", "SC");
             //DH calculation
         }catch(GeneralSecurityException e){
             //handle exception here
         }
         return k;
     }

     public Pair KDF_RK(Key root, KeyPair output){
        Pair k = null;
        byte[] rootK = root.getEncoded();
        byte[] outputMaterial;
        try{
            Mac mac = Mac.getInstance("SHA256");//change
            //HKDF using SHA-256 or 512
            //root as salt, output as input,
            //make own HDKF or use github api I found
        }catch(GeneralSecurityException e){

        }

        //KeyPair cannot do getEncoded because it two keys so probbaly needs to be
         //byte[] in function itself
         //so output of diffie hellman is byte[] too??

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
     public Pair KDF_CK(Key chain){
        Pair k = null;
        //need to turn string chain key into speicific kind of key like SecretKeySpec
         //new SecretKeySPec(key.getBytes("UTF-8"), "AES") for example
         //so elliptic version?
         //byte[] chains =
         try{

             Mac HMAC_SHA256 = Mac.getInstance("HmacSHA256");
             HMAC_SHA256.init(chain);

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

     public String encrypt(Key messageKey, String plainText, byte[] data){
        String s = "";
        try{
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        }catch(GeneralSecurityException e){

        }
        return s;
     }

     public String decrypt(Key messageKey, String cipherText, byte[] data){
        String s = "";
        try{
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            //with 16-byte IV
        }catch(GeneralSecurityException e){

        }
        //returns AEAD decryption os ciphertext with message key
         //authentication fails, exception
        return s;
     }

     public Header header(KeyPair dhPair, int chainLength, int messageNumber){
        Header header = new Header();
        //create new message header containing DH ratchet public key from the key pair
         //Header Object?
        return header;
     }

     public byte[] hencrypt(Key headerKey, String plainText){
        byte[] bytes = new byte[30];
        //AEAD encryption of plaintext with header key
         //nonce must be either non-repeating or ranodm non-repeating chosen with
         //128 bits of entropy
        return bytes;
     }

     public byte[] hdecrypt(Key headerKey, String plaintext){
        byte[] bytes = new byte[20];
        //AEAD, if authentication fails or headerKey is empty, return NONE
        return bytes;
     }
    //headers contain ratchet public keys and (PN, N) values
    //each party stores symmetric header key and next header key
    //for sending and receiving
    //////After associating the message with a session, the recipient
    //attempts to decrypt the header with that session's receiving
    // header key, next header key, and any header keys corresponding
    // to skipped messages. Successful decryption with the next header
    // key indicates the recipient must perform a DH ratchet step. During a
    // DH ratchet step the next header keys replace the current header keys, and
    // new next header keys are taken as additional output from the root KDF.
    ///////To implement the DH ratchet, each party generates a DH key pair
    //(a Diffie-Hellman public key and private key) which becomes their current
    // ratchet key pair. Every message from either party begins with a header which
    // contains the sender's current ratchet public key. When a new ratchet public key
    // is received from the remote party, a DH ratchet step is performed which replaces
    // the local party's current ratchet key pair with a new key pair.
    ////////The DH outputs generated during each DH ratchet step are used to derive new
    //sending and receiving chain keys. The below diagram revisits Bob's first ratchet
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
     public Key kdf_rk_he(State state, Key root, KeyPair output){
        Key k = null;
         //returns new root key, chain key, and next header key as output of applying
         //KDF keyed by root jey ot DH output
         //how to return all three??
        return k;
     }
     public byte[] concat(byte[] seq, Header header){
        byte[] s = null;
        //encodes message header into parsable byte seq, prepends ad and returns
         //result.
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
        Key messageKey = null;
        Pair<Header, Key> k = null;//header key or string? byte[]??
        Pair<Key, Key> pair = KDF_CK(state.chainKeyReceiving);
        state.chainKeyReceiving = pair.first;
        messageKey = pair.second;
        Header header = header(state.sendingKey, state.numberOfMessagesInChain, state.messageNumberSent);
        state.messageNumberSent++;
        k = new Pair(header, encrypt(messageKey, plainText, concat(associatedData, header)));
        return k;
    }

    public String ratchetDecrypt(State state, Header header, String cipherText, byte[] associated){
        String plainText = TrySkippedMessageKeys(state, header, cipherText, associated);
        if(plainText != null){
            return plainText;
        }
        if(header.dh != state.receivingKey){
            SkipMessageKeys(state, header.numberOfMessagesInPReviousChain);
            DHRatchet(state, header);
        }
        SkipMessageKeys(state, header.n);
        Pair<Key, Key> pair = KDF_CK(state.chainKeyReceiving);
        state.chainKeyReceiving = pair.first;
        Key messageKey = pair.second;
        state.messageNumberReceived++;
        return decrypt(messageKey, cipherText, concat(associated, header));
    }

    public String TrySkippedMessageKeys(State state, Header header, String cipherText, byte[] AD){
       if(state.skippedMessages.containsKey(header.dh) && state.skippedMessages.get(header.dh)== header.n){
           Key messageKey = null;
           //mk = state.MKSKIPPED[header.dh, header.n]
           //go from python which does this to java??
           return decrypt(messageKey, cipherText, concat(AD, header));
       }
       else {return null;}

    }

    public void SkipMessageKeys(State state, int until){
        if (state.messageNumberReceived + max_skip < until){
            //raise Error()
        }
        if (state.chainKeyReceiving != null)//or none?
                while (state.messageNumberReceived < until){
                    Pair<Key, Key> receivingMessagePair = KDF_CK(state.chainKeyReceiving);
                    state.chainKeyReceiving = receivingMessagePair.first;
                    Key messageKey = receivingMessagePair.second;
                    //state.skippedMessages.get(state.receivingKey) = messageKey;
                    state.messageNumberReceived += 1;
                }

    }

    public void DHRatchet(State state, Header header){
            state.numberOfMessagesInChain = state.messageNumberSent;
            state.messageNumberSent = 0;
            state.messageNumberReceived = 0;
            state.receivingKey = header.dh;
            Pair<Key, Key> rootReceivingPair = KDF_RK(state.rootKey, DH(state.sendingKey, state.receivingKey));
            state.rootKey = rootReceivingPair.first;
            state.chainKeyReceiving = rootReceivingPair.second;
            state.sendingKey = generate_DH();
            Pair<Key, Key> rootSendingPair = KDF_RK(state.rootKey, DH(state.sendingKey, state.receivingKey));
            state.rootKey = rootSendingPair.first;
            state.chainKeySending = rootSendingPair.second;
    }
}
