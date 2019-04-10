package com.example.messagingappencrypted;

import android.security.keystore.KeyGenParameterSpec;
import android.util.Pair;

import java.security.Key;
import java.security.KeyPair;
import java.security.Signature;
import java.security.*;

import javax.crypto.Cipher;
import javax.crypto.*;

public class KeyAgreement {

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

     public String encrypt(Key messageKey, String plainText, String data){
        String s = "";
        try{
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        }catch(GeneralSecurityException e){

        }
        return s;
     }

     public String decrypt(Key messageKey, String cipherText, String data){
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

     public String header(KeyPair dhPair, int chainLength, int messageNumber){
        String s = "";
        //create new message header containing DH ratchet public key from the key pair
         //Header Object?
        return s;
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
     public Key kdf_rk_he(Key root, KeyPair output){
        Key k = null;
         //returns new root key, chain key, and next header key as output of applying
         //KDF keyed by root jey ot DH output
         //how to return all three??
        return k;
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
    public Key ratchetEncrypt(String plainText, byte[] associatedData){
        Key k = null;
        //Pair p = KDF_CK(SUer.SendingKey); User.SendingKey = p.first;
        //user.MessageKey = p.second;
        //header = HEADER(user.sending, user.previousNumberInMessageChain,
        // user.numberSending); user.numberSending++; return pair
        //(header, ENCRYPT(messageKey, plaintext, CONCAT(associatedData, header)));
        return k;
    }

    public String ratchetDecrypt(){
        //If the message corresponds to a skipped message key this function decrypts the
        // message, deletes the message key, and returns.
        //Otherwise, if a new ratchet key has been received this function stores any skipped
        //message keys from the receiving chain and performs a DH ratchet step to replace the
        //sending and receiving chains.
        //This function then stores any skipped message keys from the current receiving chain,
        //performs a symmetric-key ratchet step to derive the relevant message key and next chain
        //key, and decrypts the message.
        //plainText = TrySkippedMessageKeys(user, header, cipherText, associated);
        //if plaintext != None: return plainText; if header.dh != user.receiving:
        //SkipMessageKeys(user, header.previous#InMesageChain); DHRATCHET(user, header);
        //SkipMessageKeys(user, header.n);
        //user.receiving, mk = KDF_CK(user.receiving)
        //    state.Nr += 1
        //    return DECRYPT(mk, ciphertext, CONCAT(AD, header))
        String s = "";
        return s;
    }

    public void TrySkippedMessageKeys(String header, String cipherText, byte[] AD){
        //if (header.dh, header.n) in state.MKSKIPPED:
        //        mk = state.MKSKIPPED[header.dh, header.n]
        //        del state.MKSKIPPED[header.dh, header.n]
        //        return DECRYPT(mk, ciphertext, CONCAT(AD, header))
        //    else:
        //        return
        //change header to header object? and based on user
    }

    public void SkipMessageKeys(int until){
        //if state.Nr + MAX_SKIP < until:
        //        raise Error()
        //    if state.CKr != None:
        //        while state.Nr < until:
        //            state.CKr, mk = KDF_CK(state.CKr)
        //            state.MKSKIPPED[state.DHr, state.Nr] = mk
        //            state.Nr += 1
    }

    public void DHRacthet(String header){
        //state.PN = state.Ns
        //    state.Ns = 0
        //    state.Nr = 0
        //    state.DHr = header.dh
        //    state.RK, state.CKr = KDF_RK(state.RK, DH(state.DHs, state.DHr))
        //    state.DHs = GENERATE_DH()
        //    state.RK, state.CKs = KDF_RK(state.RK, DH(state.DHs, state.DHr))
    }
}
