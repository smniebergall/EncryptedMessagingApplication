package com.example.messagingappencrypted;

import android.security.keystore.KeyGenParameterSpec;
import android.util.Log;
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
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPrivateKeySpec;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.KeySpec;
import java.util.Arrays;
import java.util.Enumeration;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import org.spongycastle.crypto.digests.SHA256Digest;
import org.spongycastle.crypto.generators.HKDFBytesGenerator;
import org.spongycastle.crypto.params.HKDFParameters;
import org.spongycastle.jce.interfaces.ECKey;
import org.spongycastle.util.encoders.Base64;

import javax.crypto.Cipher;
import javax.crypto.*;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import co.chatsdk.core.types.KeyValue;

public class KeyAgreement {
    int max_skip = 7;//what is good max skip amount??

    public KeyAgreement(){

    }
    public byte[] encodePub(Key pub){
        byte[] bytes;
        java.security.interfaces.ECPublicKey publ = (java.security.interfaces.ECPublicKey)pub;
        ECPoint w = publ.getW();//maybe need to change this to getting x and y from encoded version??
        bytes = concat(w.getAffineX().toByteArray(), w.getAffineY().toByteArray());
        return bytes;
    }
    public byte[] encodePriv(Key key){
        byte[] bytes;
        ECPrivateKey privKey = (ECPrivateKey)key;
        bytes = privKey.getS().toByteArray();
        return bytes;
    }
    public Key decodePub(byte[] bytes){//spec is from a ECPublicKey.getParams()
        Key key = null;
        try{
            byte[] x = new byte[32];
            byte[] y = new byte[32];
            System.arraycopy(bytes, 0, x, 0, 32);
            System.arraycopy(bytes, 32, y, 0, 32);
            KeyFactory factory = KeyFactory.getInstance("EC");
            AlgorithmParameters params = AlgorithmParameters.getInstance("EC");
            params.init(new ECGenParameterSpec("secp256r1"));
            ECParameterSpec ecSpec = params.getParameterSpec(ECParameterSpec.class);
            ECPublicKeySpec ecPublicKey = new ECPublicKeySpec(new ECPoint(new BigInteger(x), new BigInteger(y)), ecSpec);
            //ECPoint w = new ECPoint(new BigInteger(1, Arrays.copyOfRange(bytes, 0, 32)), new BigInteger(1, Arrays.copyOfRange(bytes, 32, 64)));
            key =(ECPublicKey) factory.generatePublic(ecPublicKey);
        }catch(Exception e){
            Log.i("IDKERROR", e.toString());
        }
        return key;
    }

    public Key decodePrivate(byte[] bytes){
        Key key = null;
        try{
            KeyFactory factory = KeyFactory.getInstance("EC");
            AlgorithmParameters params = AlgorithmParameters.getInstance("EC");
            params.init(new ECGenParameterSpec("secp256r1"));
            ECParameterSpec ecSpec = params.getParameterSpec(ECParameterSpec.class);
            ECPrivateKeySpec ecPrivateKey = new ECPrivateKeySpec(new BigInteger(bytes), ecSpec);
            key = (java.security.interfaces.ECPrivateKey)factory.generatePrivate(ecPrivateKey);
        }catch(Exception e){
            Log.i("IDK", e.toString());
        }
        return key;
    }
    public Key calculateSecretKey(User user, Key IKO, Key SPKO, byte[] signedPrekeyO, Key OPKO){
        //verify prekeysignature
        //then generate ephemeral here if verified
        //otherwise abort
        Log.i("IDK", "In key agreement calculate ");
        user.generateNewEphemeral();
        byte[] dh1 = null;
        byte[] dh2 = null;
        byte[] dh3 = null;
        byte[] dh4 = null;
        try{
            //bundle2.identity, bundle2.signedPreKey, bundle2.signedPreKeyBytes, bundle2.pickPrekeyToSend()
            //this, IdentityOtherPub, SignedPreKeyOtherPub, signatureOfPreKeyOtherPub, oneTimePreKeyOtherpub
            dh1 = DH(user.actualBundle.identity, SPKO);//idnetity is considered null object??
            Log.i("IDK","In calcuate secret key, dh1: " + dh1);
        }catch(Exception e){
            Log.i("IDKERRORdh1", e.toString());
        }
        //do logs up here for which class these keys are
        //maybe can do secret key for ECDH
        Log.i("IDK", "key agreement ephemeral: " + user.ephemeral);
        try{
            dh2 = DH(user.ephemeral, IKO);
            Log.i("IDK","In calcuate secret key, dh2: " + dh2);
        }catch(Exception e){
            Log.i("IDKERRORdh2", e.toString());
        }
        try{
            dh3 = DH(user.ephemeral, SPKO);
            Log.i("IDK","In calcuate secret key, dh3: " + dh3);
        }catch(Exception e){
            Log.i("IDKERRORdh3", e.toString());
        }
        Key secret = null;
        //maybe not current users prekey, make a new ephemeral key for this
        if(OPKO != null){
            try{
                dh4 = DH(user.ephemeral, OPKO);
                Log.i("IDK","In calcuate secret key, dh4: " + dh4);
                //byte[] concated = concat(concat(concat(dh1.getEncoded(), dh2.getEncoded()), dh3.getEncoded()), dh4.getEncoded());//error index out of bound??
                //byte[] dh1Bytes = encodePub(dh1);
                //byte[] dh2Bytes = encodePub(dh2);
                //byte[] dh3Bytes = encodePub(dh3);
                //byte[] dh4Bytes = encodePub(dh4);
                //byte[] dh4Bytes = dh4.getEncoded();
                //byte[] dh1BytesX = Arrays.copyOfRange(dh1Bytes, 0, 32);//clean this up??
                //byte[] dh2BytesX = Arrays.copyOfRange(dh2Bytes, 0, 32);
                //byte[] dh3BytesX = Arrays.copyOfRange(dh3Bytes, 0, 32);
                //byte[] dh4BytesX = Arrays.copyOfRange(dh4Bytes, 0, 32);
                byte[] concated = concat(concat(concat(dh1, dh2), dh3), dh4);
                Log.i("IDK", "in calculate secret key, concated for 4 dh's: " + concated);//wrong place now moved
                //so why in DH is a null??
                secret = KDF(concated);
            }catch(Exception e){
                Log.i("IDKERRORdh4", e.toString());

            }
            //maybe change ephemeral to actual key bundle??
        }
        else
        {
            //byte[] concated = concat(concat(dh1.getEncoded(), dh2.getEncoded()), dh3.getEncoded());
            //byte[] dh1Bytes = encodePub((java.security.interfaces.ECPublicKey)dh1);
            //byte[] dh2Bytes = encodePub((java.security.interfaces.ECPublicKey)dh2);
            //byte[] dh3Bytes = encodePub((java.security.interfaces.ECPublicKey)dh3);
            //byte[] dh1BytesX = Arrays.copyOfRange(dh1Bytes, 0, 32);
            //byte[] dh2BytesX = Arrays.copyOfRange(dh2Bytes, 0, 32);
            //[] dh3BytesX = Arrays.copyOfRange(dh3Bytes, 0, 32);
            byte[] concated = concat(concat(dh1, dh2), dh3);
            Log.i("IDK", "in calculate secret key, concated for 3 dh's: " + concated);
            secret = KDF(concated);
        }
        Log.i("IDK", "In calculateSecretKey");
        Log.i("IDK", "In calculate secret key, secret: "+ secret);
        return secret;
    }
    public byte[] initialMessage(Key IKA, Key IKB, Key EKA, int[] identifiers, byte[] ciphertext){
        Log.i("IDK", "in initial in key agreement");
        Log.i("IDK", "IKA length: " + IKA.getEncoded().length);
        Log.i("IDK", "IKa : " + IKA.getAlgorithm());
        Log.i("IDK", "EKA length: " + EKA.getEncoded().length);

        byte[] bytes;
        //byte[] IKAEncoded = encodePub(IKA);
        //byte[] EKAEncoded = encodePub(EKA);
        Log.i("IDK", "IKA to string encoded bytes length: " + IKA.toString().getBytes().length);//IKA.toString().getBytes();
        byte[] stuff = Arrays.copyOfRange(IKA.getEncoded(), 0, 64);
        byte[] stuff2 = Arrays.copyOfRange(EKA.getEncoded(), 0, 64);
        Log.i("IDK", "IKA but only first 64 bytes: " + stuff.length);
        //byte[] first = concat(IKA.getEncoded(), EKA.getEncoded());
        byte[] first = concat(stuff, stuff2);
        Log.i("IDK", "in initial in key agreement, finisheed first concat, length: " + first.length);
        byte[] ids = ByteBuffer.allocate(8).putInt(identifiers[0], identifiers[1]).array();//4 instead of 1??
        byte[] ids2 = ByteBuffer.allocate(8).putInt(identifiers[2], identifiers[3]).array();
        byte[] actualids = concat(ids, ids2);
        Log.i("IDK", "initial message, ids: " + actualids.length);//8
        byte[] second = concat(first, actualids);//buffer overflow
        Log.i("IDK", "in initial in key agreement, finisheed second concat, length: " + second.length);
        Log.i("IDK", "in initial, ciphertext length : " + ciphertext.length);
        bytes = concat(second, ciphertext);//buffer overflow, maybe split up concats?
        Log.i("IDK", "in initial in key agreement, finisheed last concat, length: " + bytes.length);//184?

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
        SecretKey k = new SecretKeySpec(result, "ECDH");
        Log.i("IDK", "In KDF");
        return k;
    }

    public byte[] sig(KeyPair pair, byte[] message){
        byte[] bytes = new byte[30];

        Log.i("IDK", "In sig before the try catch");
        Log.i("IDK", "Public: " + pair.getPublic().toString());
        Log.i("IDK", "Private: " + pair.getPrivate().toString());
        //maybe 25519 for signature??
        try{
            Log.i("IDK", "In sig");
            Signature signature = Signature.getInstance("SHA256withECDSA");
            signature.initSign(pair.getPrivate());
            signature.update(message);
            bytes = signature.sign();//length of 71??
            Log.i("IDK", "Key sign finished: ");
            Log.i("IDK", "Key sign finished, bytes: " + bytes);
            Log.i("IDK", "Key sign finished, bytes length: " + bytes.length);
            //just sign and verify??
        }catch(GeneralSecurityException e){
            Log.i("IDKERRORsig", e.toString());
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
        //these need to be ECPublicKey
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
            KeyPairGenerator generator = KeyPairGenerator.getInstance("ECDH");
            generator.initialize(new ECGenParameterSpec("secp256r1"));
            k = generator.generateKeyPair();
            //java says this exists, android developers says it doesn't?
            //share key with server (String)(Base65.encode(pubKeu.encoded, 0)) maybe?
            //maybe with spongy castle?
            Log.i("IDK", "In generate_DH");
        }catch(GeneralSecurityException e){
            //handle exception here
            Log.i("IDKERRORgenerateDH", e.toString());
        }
        return k;
    }
     public byte[] DH(KeyPair pair, Key pub){
        //DH calculation using pair private key and public
         Key k = null;
         Key a = null;
         byte[] key = null;
         try{
             //PublicKey k = (ECPublicKey)pub;
             javax.crypto.KeyAgreement agree = javax.crypto.KeyAgreement.getInstance("ECDH");//this is the source of error

             //agree.init(Key, AlgorithmParameterSpec);// pair.getPrivate(), and
             //agree.init(new ECParameterSpec("secp256r1"), pair.getPrivate());
             //two SecretKeySpecs and one ECPrivateKey
             Log.i("IDK", "In DH, pair.private() : " + pair.getPrivate());
             Log.i("IDK", "In DH, public key : " + pub);
             agree.init(pair.getPrivate());
             a = agree.doPhase(pub, true);//why odes this return null??
             //k = agree.generateSecret("ECDH");
             key = agree.generateSecret();
             Log.i("IDK", "Finish DH, a : " + a);
             Log.i("IDK", "Finish DH, byte[] key length : " + key.length);
             //should i do below??
             //bytes = agree.generateSecret();
         }catch(GeneralSecurityException e){
             //handle exception here
             Log.i("IDKERRORDH", e.toString());
         }
         return key;
     }

     public Pair<Key, Key> KDF_CK(Key chain){
        Pair<Key, Key> k = null;
         try{
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
             SecretKey mkey = new SecretKeySpec(messageKey, "ECDH");

             SecretKey ckey = new SecretKeySpec(nextChainKey, "ECDH");
             k = new Pair(mkey, ckey);
             Log.i("IDK", "In KDF_CK");
         }catch(GeneralSecurityException e){
             Log.i("IDKERRORKDFCK", e.toString());
         }
        return k;
     }

     public byte[] encrypt(Key messageKey, byte[] plainText, byte[] data){
         byte[] bytes = null;
         Log.i("IDK", "In encypt, before try");
         try{
             //spongy castle does HKDF
             Log.i("IDK", "In encrypt");
            byte[] salt = new byte[80];
            byte[] info;
            String s = "info for HKDF";
            info = s.getBytes(Charset.forName("UTF-8"));
            //byte[] messagekey = messageKey.getEncoded();
             byte[] messagekey = messageKey.getEncoded();
            HKDFParameters params = new HKDFParameters(messagekey, salt, info);
            HKDFBytesGenerator hkdf = new HKDFBytesGenerator(new SHA256Digest());
            hkdf.init(params);
            byte[] result = new byte[80];
            hkdf.generateBytes(result, 0,80);
             Log.i("IDK", "In encrypt, result: " + result);
            byte[] encryptionKey = new byte[32];
            byte[] authKey = new byte[32];
            byte[] IV = new byte[16];
            for(int i = 0; i < 32; i++){
                encryptionKey[i] = result[i];
            }
             Log.i("IDK", "In encrypt, encryptionKey bytes: " + encryptionKey);
            for(int i = 32; i < 64; i++){
                authKey[i-32] = result[i];//index out of bounds
            }
             Log.i("IDK", "In encrypt, authKey bytes: " + authKey);
            for(int i = 64; i < result.length; i++){
                IV[i-64] = result[i];
            }
             Log.i("IDK", "In encrypt, IV bytes: " + IV);
             Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
             IvParameterSpec iv = new IvParameterSpec(IV);
             Log.i("IDK", "In encrypt, iv spec: " + iv);
             SecretKeySpec encKey = new SecretKeySpec(encryptionKey, "HMAC_SHA256");
             Log.i("IDK", "In encrypt, encKey: " + encKey);
             SecretKeySpec aKey = new SecretKeySpec(authKey, "HMAC_SHA256");
             Log.i("IDK", "In encrypt, aKey: " + aKey);
             cipher.init(Cipher.ENCRYPT_MODE, encKey, iv);
             byte[] encrypted = cipher.doFinal(plainText);
             Log.i("IDK", "In encrypt, encrypted: " + encrypted);
             Mac mac = Mac.getInstance("HmacSHA256");
             mac.init(aKey);
             byte[] hmac = mac.doFinal(concat(data, encrypted));
             Log.i("IDK", "In encrypt, hmac: " + hmac);
             bytes = new byte[hmac.length+encrypted.length];
             System.arraycopy(encrypted, 0, bytes, 0, encrypted.length);
             System.arraycopy(hmac, 0, bytes, encrypted.length, hmac.length);
             Log.i("IDK", "In encrypt, bytes: " + bytes);
             Log.i("IDK", "In encrypt, bytes length: " + bytes.length);
             Log.i("IDK", "Finish encrypt");
         }catch(GeneralSecurityException e){
             Log.i("IDKERRORencrypt", e.toString());
         }
        return bytes;
     }

     public byte[] decrypt(Key messageKey, byte[] cipherText, byte[] data){
        byte[] bytes = null;
         Log.i("IDK", "In decrypt");
        SecureRandom s = new SecureRandom();
        IvParameterSpec IV;
        byte[] ivBytes = new byte[16];
        s.nextBytes(ivBytes);
        IV = new IvParameterSpec(ivBytes);
         Log.i("IDK", "In decrypt, IV: "+ IV);
         Log.i("IDK", "ciphertext length: " + cipherText.length);
        try{
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.DECRYPT_MODE, messageKey, IV);
            //byte[] tryArray = Arrays.copyOf(cipherText, 176);//try truncating??
            byte[] decrypted = cipher.doFinal(cipherText);
            Log.i("IDK", "In decrypt, decrypted: "+ decrypted);
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(messageKey);
            byte[] hmac = mac.doFinal(concat(data, decrypted));
            Log.i("IDK", "In decrypt, hmac: "+ hmac);
            bytes = new byte[hmac.length+decrypted.length];
            System.arraycopy(decrypted, 0, bytes, 0, decrypted.length);
            System.arraycopy(hmac, 0, bytes, decrypted.length, hmac.length);
            Log.i("IDK", "In decrypt, bytes: "+ bytes);
            Log.i("IDK", "Finish decrypt");
            //if authentictaion fails, exception is raised
            //but what is associated data and hwo does authentication fail
            //it has to match something right?? what??
        }catch(GeneralSecurityException e){
            Log.i("IDKERRORdecrypt", e.toString());
        }
         Log.i("IDK", "Finish decrypt");
        return bytes;
     }

     public byte[] header(KeyPair dhPair, int chainLength, int messageNumber){
        byte[] bytes = new byte[40];
        byte[] n;
        byte[] pmic;
        byte[] dh;
        n = ByteBuffer.allocate(4).putInt(messageNumber).array();
        pmic = ByteBuffer.allocate(4).putInt(chainLength).array();
        //dh = dhPair.getPublic().getEncoded();
        //byte[] dhFull = encodePub(dhPair.getPublic());
        //dh = Arrays.copyOfRange(dhFull, 0, 32);
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
            Log.i("IDK", "In hencrypt");
        }catch(GeneralSecurityException e){
            Log.i("IDKERRORhencrypt", e.toString());
        }
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
            SecretKey dh = new SecretKeySpec(k, "ECDH");
            Log.i("IDK", "In hdecrypt");
            header.updateHedaer(new BigInteger(n).intValue(), new BigInteger(pmic).intValue(), dh);
        }catch(GeneralSecurityException e){
            Log.i("IDKERRORhdecrypt", e.toString());
        }
        //AEAD, if authentication fails or headerKey is empty, return NONE
        return header;
     }
    //To allow Bob and ALice to send messages immediately after initialization Bob's
    // sending chain key and Alice's receiving chain key could be initialized to a
    // shared secret.
     public Pair<Pair<Key, Key>, Key> kdf_rk_he(State state, Key root, byte[] output){
         //returns new root key, chain key, and next header key as output of applying
         //KDF keyed by root key to DH output
         //how to return all three??
         //probbaly still EC DH key??
         Pair<Pair<Key, Key>, Key> keys = null;
         //try{
             byte[] info;
             String s = "HKDF for lots of keys";
             info = s.getBytes(Charset.forName("UTF-8"));
             //HKDFParameters params = new HKDFParameters(root.getEncoded(), output.getEncoded(), info);
             HKDFParameters params = new HKDFParameters(root.getEncoded(), output, info);//32 byte version or just normal 64 ish one??
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
             /*KeyFactory kf = KeyFactory.getInstance("ECDH");//may not need this
             AlgorithmParameters params = AlgorithmParameters.getInstance("EC");
             params.init(new ECGenParameterSpec("secp256r1"));
             ECParameterSpec ecSpec = params.getParameterSpec(ECParameterSpec.class);
             ECPrivateKeySpec ecPrivateKey = new ECPrivateKeySpec(new BigInteger(bytes), ecSpec);*/
             SecretKey rkey = new SecretKeySpec(rootKeyResult,  "ECDH");//AES is 32-byte i think
             SecretKey ckey = new SecretKeySpec(chainKeyResult,  "ECDH");
             SecretKey nkey = new SecretKeySpec(nextHeaderKey, "ECDH");
             Log.i("IDK", "In kdf_rk_he");
             keys = new Pair(new Pair(rkey, ckey), nkey);
             //256 bits key is 32-byte array
         //}catch(GeneralSecurityException e){
           //  Log.i("IDKERRORkdfrkhe", e.toString());
         //}
         //Pair<Pair<RootKey, ChainKey>, nextHeaderKey>
         return keys;
     }
     public byte[] concat(byte[] seq, byte[] header){
        byte[] s = new byte[header.length+seq.length];
        System.arraycopy(seq, 0, s , 0, seq.length);
        System.arraycopy(header, 0, s, seq.length, header.length);
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
        Pair<Header, byte[]> k;
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
}
