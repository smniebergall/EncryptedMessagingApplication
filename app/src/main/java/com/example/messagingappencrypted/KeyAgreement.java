package com.example.messagingappencrypted;

import android.util.Pair;

import java.security.Key;
import java.security.KeyPair;

public class KeyAgreement {

    public KeyAgreement(){

    }
    //X3DH and elliptical curve diffie-hellman
    //SHA-256 or SHA-512 for hash
    //curve is X25519 or X448
    //info identifying application
    //Encode(PK): encode curve public key into byte sequence, recommended
    //single-byte constant to represent type of curve, followed by little-
    //endian encoding of the u-coordinate
    //for curve X25519 prime 2^255-19 is recommended
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

    public byte[] computeMasterKey(){
         byte[] b = new byte[256];
         //bytes or keys?????
         //compute master key with X3DH
         return b;
    }

    public void sendMessage(){
        //DOuble ratchet to recieve and send encrypted messages
    }

    public Key KDF(Key secret){
        Key k = null;
        //two symmetric keys
        //may need these to be global? for each user?
        //attaches this key to message to send
        //info is in user and public
        //HMAC and HKDF together create KDF
        //ALice and bob both store KDF key of root, sending, and reciecing
        //a's sending matches b's recieving
        //as a and b exchange messages, they also exchange new dh public keys
        //and dh output secrets become the inputs to the root chain
        //output keys of root chain become new KDF keys for sending and
        //receiving chains
        //sending and receiving chains advance as each message is sent and received
        //their output is used to encrypt and decrypt messages(symmetric key ratchet)

        return k;
    }

    public void symmetricKeyRatchet(){
        //every message sent or received is encrypted with a unique message key
        //message keys are output keys from sending and recieving KDF chains
        //these are called chian keys
        //inputs for sending and recieving chains are constant
        //used for unique key that can encrypt with and be deleted
        //when new ratchet public key is recieved from remote party,
        //current ratchet key pair ir replaced with new key pair
        //dh outputs put into KDF to create root chain, and the outputs of KDf
        //used as sending and recieving chian keys
    }

    public void DHRatchet(){
        //updates chain keys based on DH outputs
        //each party generates a DH key pair, which becomes current ratchet key pair
        //each message from either party starts with current ratchet public key
        //
    }

    public void doubleRatchet(){
        //when message is recieved or sent, symmetric-key ratchet step is applied to
        //sending or recieving chain to derive message key
        //when new ratchet public key received, dh ratchet step performed prior
        //to symmetric-key rathcte to replace chain keys
    }
    public void AES(String message){
        //
    }

    public String HMAC(){
        String s = "";
        //HMAC-SHA256
        //output hash is 256 bits in length
        return s;
    }

    public void sendMessage(String s){
        //check if key bundle has "count" of 3 for no prekey and 4
        //for a one-time prekey
    }

//required ofr double ratchet
    public void X3DH(){
        //handles
    }

    public KeyPair generate_DH(){
        KeyPair k = null;
        //returns new DH key pair
        return k;
    }

     public KeyPair DH(KeyPair pair, Key pub){
        //DH calculation using pair private key and pub
         //if invalid public keys, exception
         /*byte[] b = new byte[256];
         return b;*/
         KeyPair k = null;
         return k;
     }

     public Pair KDF_RK(Key root, KeyPair output){
        Pair k = null;
        //regular pair or kaypair??
        //(32 root key, 32 chain key);
         //output of applying KDF keyed by a 32 byte root key to a DH output
        return k;
     }

     public Pair KDF_CK(Key chain){
        Pair k = null;
        //(32-byte chain key, 32-byte message key);
         //applying KDF keyed by a 32 byte chian key to come constant
        return k;
     }

     public String encrypt(Key messageKey, String plainText, String data){
        String s = "";
        //AEAD encryption of plaintext w/ message key. Data is authenticated
         //because each message key used once,
         //AEAD nonce may be handled  by a fixed constant, or derived from message key
         //alongside independent AEAD encryption key
        return s;
     }

     public String decrypt(Key messageKey, String cipherText, String data){
        String s = "";
        //returns AEAD decryption os ciphertext with message key
         //authentication fails, exception
        return s;
     }

     public String header(KeyPair dhPair, int chainLength, int messageNumber){
        String s = "";
        //create new message header containing DH ratchet public key from the key pair
         //Header Object?
        return s;
     }

     public String concat(byte[] seq, String header){
        String s = "";
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
    //

}
