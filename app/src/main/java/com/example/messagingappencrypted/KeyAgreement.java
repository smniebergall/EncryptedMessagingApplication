package com.example.messagingappencrypted;

import java.security.Key;

public class KeyAgreement {
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

    public Key computeMasterKey(){
         Key k = null;
         //compute master key with X3DH
         return k;
    }

    public void sendMessage(){

    }

    public Key KDF(Key root, Key chainKey){
        Key k = null;
        //two symmetric keys
        //may need these to be global? for each user?
        //attaches this key to message to send
        //info is in user and public
        return k;
    }

    public void AES(){

    }

    public String HMAC(){
        String s = "";
        //HMAC-SHA256
        //output hash is 256 bits in length
        return s;
    }

}
