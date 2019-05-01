package com.example.messagingappencrypted;

import androidx.appcompat.app.AppCompatActivity;
import androidx.constraintlayout.widget.ConstraintLayout;
import androidx.core.app.NotificationCompat;
import co.chatsdk.core.session.ChatSDK;
import co.chatsdk.core.session.NetworkManager;
import co.chatsdk.core.types.AccountDetails;
import co.chatsdk.core.utils.StringChecker;
import co.chatsdk.ui.chat.options.BaseChatOption;
import co.chatsdk.ui.main.BaseActivity;
import io.reactivex.android.schedulers.AndroidSchedulers;
import io.reactivex.disposables.Disposable;
import io.reactivex.functions.Action;
import io.reactivex.functions.Consumer;
import timber.log.Timber;
import android.app.Notification;
import android.content.Context;
import android.content.Intent;
import android.drm.DrmStore;
import android.graphics.Point;
import android.net.ConnectivityManager;
import android.net.NetworkInfo;
import android.os.Bundle;
import android.text.TextUtils;
import android.util.Log;
import android.view.View;
import android.widget.Button;
import android.widget.Toast;

import com.firebase.client.Config;
import com.firebase.client.Firebase;
import com.google.android.material.button.MaterialButton;
import com.google.android.material.textfield.TextInputEditText;
import com.google.firebase.database.DatabaseReference;
import com.google.firebase.database.FirebaseDatabase;

//import org.apache.commons.lang3.StringUtils;

import org.spongycastle.jce.ECNamedCurveTable;
import org.spongycastle.math.ec.ECCurve;
import org.spongycastle.math.ec.ECFieldElement;
import org.spongycastle.math.ec.ECPoint;

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.*;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.SecretKeySpec;

//change email edit to show fully what youre typing
//authenticating seems to just keep doing it?

public class MyLoginActivity extends BaseActivity implements View.OnClickListener {
    //AppCompatActivity
    protected boolean exitOnBack = false;
    protected ConstraintLayout mainView;
    protected boolean auth = false;
    protected DatabaseReference database;
    protected TextInputEditText usernameEdit;
    protected TextInputEditText passwordEdit;

    protected Button buttonLogin, buttonRegister;//reset password?

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_my_login);
        setExitOnBackPressed(true);
        mainView = findViewById(R.id.chat_sdk_root_view);
        //setupTouchUIToDismissKeyboard(mainView);
        database = FirebaseDatabase.getInstance().getReference();
        initViews();
        if (getSupportActionBar() != null) {
            getSupportActionBar().hide();
        }

    }

    protected void initViews() {
        buttonLogin = findViewById(R.id.login_button);
        buttonRegister = findViewById(R.id.button_register);
        usernameEdit = findViewById(R.id.username_edit);
        passwordEdit = findViewById(R.id.password_edit);
        //reset password button?

        if (!StringChecker.isNullOrEmpty(ChatSDK.config().debugUsername)) {
            usernameEdit.setText(ChatSDK.config().debugUsername);
        }
        if (!StringChecker.isNullOrEmpty(ChatSDK.config().debugPassword)) {
            passwordEdit.setText(ChatSDK.config().debugPassword);
        }
    }

    @Override
    protected void onActivityResult(int requestCode, int resultCode, Intent data){
        super.onActivityResult(requestCode, resultCode, data);
        if(ChatSDK.socialLogin() != null){
            //ChatSDK.socialLogin().onActivityResult();
        }//what is this?
    }

    protected void initListeners() {
        buttonLogin.setOnClickListener(this);
        buttonRegister.setOnClickListener(this);
        //reset password button
    }

    @Override
    public void onClick(View view) {
        int i = view.getId();
        Action completion = this::afterLogin;
        Consumer<Throwable> error = throwable -> {
            ChatSDK.logError(throwable);
            Toast.makeText(MyLoginActivity.this, throwable.getLocalizedMessage(), Toast.LENGTH_LONG).show();
        };
        //Action doFinally = this::dismissProgressDialog;
        showProgressDialog(getString(R.string.authenticating));
        if (i == R.id.login_button) {
            passwordLogin();
        } else if (i == R.id.button_register) {
            register();
        }
        //reset password
    }
    @Override
    protected void onResume () {
        super.onResume();
        initListeners();
    }

    protected void afterLogin () {
        //ChatSDK.ui().startMainActivity(getApplicationContext());
        TryActualEncryptionDecryption();
        finish();
    }

    public void passwordLogin () {
        if (!checkFields()) {
            dismissProgressDialog();
            return;
        }
        if (!isNetworkAvailable()) {
            Timber.v("Network Connection unavailable");
        }
        AccountDetails details = AccountDetails.username(usernameEdit.getText().toString(), passwordEdit.getText().toString());
        authenticateWithDetails(details);

    }

    public void authenticateWithDetails(AccountDetails details){
        if(auth){
            return;
        }
        auth = true;
        //never gets to connecting...
        showProgressDialog("Connecting...");
        Disposable d = ChatSDK.auth().authenticate(details).observeOn(AndroidSchedulers.mainThread())
                .doFinally(() -> {
                    auth = false;
 //                   dismissProgressDialog();
                })
                .subscribe(this::afterLogin, e -> {
                    dismissProgressDialog();
                    toastErrorMessage(e, false);
                    ChatSDK.logError(e);
                });
    }

    @Override
    public void onStop(){
        super.onStop();
        dismissProgressDialog();
    }

    public void register(){
        if(!checkFields()){
            dismissProgressDialog();
            return;
        }
        AccountDetails details = new AccountDetails();
        details.type = AccountDetails.Type.Register;
        details.username = usernameEdit.getText().toString();
        details.password = passwordEdit.getText().toString();
        authenticateWithDetails(details);
        //maybe do it here which means custom authenicate
        //ChatSDKAbstractLoginActivity.java
        //generateKeys(): need long-term identity keys, medium-term
        // signed prekey, and several ephermeral prekey pairs
        //on this side and stored locally.
        //Then bundle all into a key bundle to register in key distribution
        //center. Android keystore system
        //identity key is public/private key pair,
        //KeyPairGenerator()
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");//does this actally work
            /*generator.initialize(256);//what size??
            //do i need to worry about 33 byte EC key to 32 byte key??
            KeyPair pair = generator.generateKeyPair();
            Key priv = pair.getPrivate();
            Key pub = pair.getPublic();
            List<KeyPair> realPrekeys = new ArrayList<KeyPair>();
            for(int i = 0; i < 10; i++){
                realPrekeys.add(generator.generateKeyPair());
            }
            List<Key> prekeys = new ArrayList<Key>();
            for(int i = 0; i < realPrekeys.size();i++){
                prekeys.add(realPrekeys.get(i).getPublic());
            }
            KeyPair actualPrekey = generator.generateKeyPair();
            Key prekey = actualPrekey.getPublic();
            String ID = ChatSDK.currentUserID();
            KeyBundle bundle = new KeyBundle(priv, prekey, prekeys);
            ActualKeyBundle realBundle = new ActualKeyBundle(ID, pair, actualPrekey, realPrekeys);
            database.child("users").child(ID).setValue(bundle);*/
            //evey once in a while, upload new signed prekey and prekey signature
            //save private of actual key bundle to phone somehow
            //get public

        }catch(NoSuchAlgorithmException e){
            //handle exception
        }
    }

    @Override
    public void onBackPressed(){
        if(exitOnBack){
            Intent intent = new Intent(Intent.ACTION_MAIN);
            intent.addCategory(Intent.CATEGORY_HOME);
            intent.setFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
            startActivity(intent);
        }
        else super.onBackPressed();
    }

    public void toastErrorMessage(Throwable error, boolean login){
        String errorMessage = "";
        //StringUtils.isNotBlank(error.getMessage())
        if(!TextUtils.isEmpty(error.getMessage())){//is this okay??
            errorMessage = error.getMessage();
        }
        else if(login){
            errorMessage = "Failed to login!";
        }
        else {
            errorMessage = "Failed to register!";
        }
        showToast(errorMessage);
    }

    protected boolean checkFields(){
        if(usernameEdit.getText().toString().isEmpty()){
            showToast("Email field is empty!");
            return false;
        }
        if(passwordEdit.getText().toString().isEmpty()){
            showToast("Password field is empty!");
            return false;
        }
        return true;
    }

     protected boolean isNetworkAvailable(){
         ConnectivityManager connectivityManager = (ConnectivityManager) getSystemService(Context.CONNECTIVITY_SERVICE);
         NetworkInfo activeNetworkInfo = connectivityManager.getActiveNetworkInfo();
         return activeNetworkInfo != null && activeNetworkInfo.isConnected();
     }

     protected void setExitOnBackPressed(boolean exitOnBack){
        this.exitOnBack = exitOnBack;
     }

     public void TryActualEncryptionDecryption(){

        Log.i("IDK", "Before try!!");
        try{
            KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");//does this actally work, shuld be 25519
            Log.i("IDK", "IN try!!");
            generator.initialize(256);//what size??
            //do i need to worry about 33 byte EC key to 32 byte key??
            KeyPair pair1 = generator.generateKeyPair();
            Key priv1 = pair1.getPrivate();
            Key pub1 = pair1.getPublic();
            List<KeyPair> realPrekeys1 = new ArrayList<KeyPair>();
            for(int i = 0; i < 10; i++){
                realPrekeys1.add(generator.generateKeyPair());
            }
            List<Key> prekeys1 = new ArrayList<Key>();
            for(int i = 0; i < realPrekeys1.size();i++){
                prekeys1.add(realPrekeys1.get(i).getPublic());
            }
            KeyPair actualPrekey1 = generator.generateKeyPair();
            Key prekey1 = actualPrekey1.getPublic();
            Log.i("IDK", "IN try!! Prekeys done!");
            /*//String ID = ChatSDK.currentUserID();
            //String ID2 = ChatSDK.currentUserID();
            //thinks the above two are still active and not commented out??*/
            String ID = "one";
            String ID2 = "two";
            User one = new User(ID);
            User two = new User(ID2);
            Log.i("IDK", "IN try!! Created users!");
            byte[] signedPrekey1 = new byte[32];
            signedPrekey1 = one.signPreKey(pair1, prekey1.getEncoded());//null object reference in here to signPreKey
            //pair1 is generated

            Log.i("IDK", "IN try!! Signed Prekeys!");
            Log.i("IDK", "IN try!! pub1 : " + pub1.toString());
            Log.i("IDK", "IN try!! prekey1 : " + prekey1.toString());
            Log.i("IDK", "IN try!! signedPrekey1 : " + signedPrekey1.toString());
            //Log.i("IDK", "IN try!! realPrekeys1 : " + realPrekeys1.toString());

            KeyBundle bundle1 = new KeyBundle(pub1, prekey1, signedPrekey1, prekeys1);
            //Key identity, Key prekey, Key signedPreKey, List<Key> prekeys
            ActualKeyBundle realBundle1 = new ActualKeyBundle(ID, pair1, actualPrekey1, realPrekeys1);
            one.updateKeyBundle(realBundle1);
            Log.i("IDK", "IN try!! finished bundle1, about to start user 2's stuff");
            KeyPair pair2 = generator.generateKeyPair();
            Key priv2 = pair2.getPrivate();
            Key pub2 = pair2.getPublic();
            List<KeyPair> realPrekeys2 = new ArrayList<KeyPair>();
            for(int i = 0; i < 10; i++){
                realPrekeys2.add(generator.generateKeyPair());
            }
            List<Key> prekeys2 = new ArrayList<Key>();
            for(int i = 0; i < realPrekeys1.size();i++){
                prekeys2.add(realPrekeys1.get(i).getPublic());
            }
            KeyPair actualPrekey2 = generator.generateKeyPair();
            Key prekey2 = actualPrekey2.getPublic();
            byte[] signedPrekey2 = two.signPreKey(pair2, prekey2.getEncoded());
            Log.i("IDK", "signedPrekey2: " + signedPrekey2);
            Log.i("IDK", "signedPrekey2 length: " + signedPrekey2.length);
            Log.i("IDK", "IN try!! Signed Prekeys for user 2 and finished prekeys and prekey signature for 2!");
            State state1 = new State();
            State state2 = new State();
            Log.i("IDK", "IN try!! States!");

            KeyBundle bundle2 = new KeyBundle(priv2, prekey2, signedPrekey2, prekeys2);
            ActualKeyBundle realBundle2 = new ActualKeyBundle(ID2, pair2, actualPrekey2, realPrekeys2);
            two.updateKeyBundle(realBundle2);
            Log.i("IDK", "IN try!! Finished all bundles");

            //key agreement protocol here!!
            //did i ever put bundles in the user??
            //Key IdentityOtherPub, Key SignedPreKeyOtherPub, Key signatureOfPreKeyOtherPub, Key oneTimePreKeyOtherpub
            Log.i("IDK", "IN try!! bundle 2 identity: " + bundle2.identity);
            Log.i("IDK", "IN try!! bundle 2 signedPrekey: " + bundle2.signedPreKey);
            Log.i("IDK", "IN try!! bundle 2 signedPrekEy bytes: " + bundle2.signedPreKeyBytes);
            Log.i("IDK", "IN try!! bundle 2 one-time prkeey: " + bundle2.pickPrekeyToSend());
            Log.i("IDK", "IN try!! bundle 1 identity pub: " + realBundle1.identity.getPublic());
            Log.i("IDK", "IN try!! bundle 1 identity priv: " + realBundle1.identity.getPrivate());
            Key secret = one.calculateSecretKey(bundle2.identity, bundle2.signedPreKey, bundle2.signedPreKeyBytes, bundle2.pickPrekeyToSend());
            Log.i("IDK", "Secret key from alice: " + secret.toString());
            //both ways is important
            //need to change bundle to have signed prekey, signature of signed prekey
            //and one time prekey
            //User user, Key IKO, Key SPKO, Key signedPrekeyO, Key OPKO
            byte[] AD = one.k.concat(bundle1.identity.getEncoded(), bundle2.identity.getEncoded());
            int[] identifiers = new int[2];
            identifiers[0] = 1;
            identifiers[1] = 1;//apprently use both
            byte[] text = "Hello, let's start a session!".getBytes();
            byte[] ciphertext = one.encryptInitialMessage(secret, text, AD);
            byte[] initialMessageFromAlice = one.k.initialMessage(bundle1.identity, bundle2.identity, one.ephemeral.getPublic(), identifiers, ciphertext);
            byte[] initialMessage = null;
            byte[] decryptedInitialMessage = null;
            byte[] IKAForB = new byte[32];
            byte[] EKAForB = new byte[32];
            byte[] ids = new byte[4];
            int id;
            int id2;
            //if initialMessageFromAlice is 78
            //
            for(int i = 0; i < 32; i++){
                IKAForB[i] = initialMessageFromAlice[i];
            }
            for(int i = 32; i < 65; i++){
                EKAForB[i-32] = initialMessageFromAlice[i];
            }
            for(int i = 65; i < 73; i++){
                ids[i-65] = initialMessageFromAlice[i];
            }
            for(int i = 73; i < initialMessageFromAlice.length; i++){
                initialMessage[i-73] = initialMessageFromAlice[i];
            }
            byte[] ids1 = new byte[4];
            byte[] ids2 = new byte[4];
            for(int i = 0; i < 4; i++){
                ids1[i] = ids[i];
            }
            for(int i = 4; i < 8; i++){
                ids2[i-4] = ids[i];
            }//technically only need one prekey and just it to make signature
            id2 = ByteBuffer.wrap(ids2).getInt();
            id = ByteBuffer.wrap(ids1).getInt();
            SecretKey ika = new SecretKeySpec(IKAForB,  "EC");

            /*SecretKeyFactory factory = SecretKeyFactory.getInstance("EC");
            SecretKey ika = factory.*/
            SecretKey eka = new SecretKeySpec(EKAForB,  "EC");
            Key secret2 = two.calculateSecretKey(ika, bundle1.signedPreKey, bundle1.getSignedPreKey().getEncoded(), bundle1.getSpecificPreKey(id));
            byte[] AD2 =  two.k.concat(bundle1.identity.getEncoded(), bundle2.identity.getEncoded());
            decryptedInitialMessage = two.decryptInitialMessage(secret2, initialMessage, AD2);
            Log.i("IDK", "Initial Message in string: " + decryptedInitialMessage.toString());
            //how to check if actually decrypted
            //maybe add button for does this make sense??
            //delete any prekey used
            Key pub = bundle2.identity;
            KeyPair priv = realBundle2.identity;
            Key sharedHeaderKey = one.findState(state1).headerSending;
            Key sharedNextHeaderKey = two.findState(state2).nextHeaderReceiving;

            one.updateUserForRatchetStart(state1, secret, pub, sharedHeaderKey, sharedNextHeaderKey);
            two.updateUserFOrRatchetSecond(state2, secret, priv, sharedHeaderKey, sharedNextHeaderKey);
            //Okay so get key bundle, A verifies prekey signature and generates
            //ephemeral key pair EKA if it if works, then do calculate secret key,
            //after, A deletes ephemeral private key, calculates associated data
            //which is AD = encoded(IKA) concated to encode(IKB)
            //A sends messages containing IKA, EKA, identifiers saying which of B's prekeys
            //used, and initial ciphertext encrypted using AEAD
            //so 32, 32, how many for prekeys, and whatevers left is ciphertext

            //When B gets message, B gets the two keys from message and loads B's
            //identity private key, and private keys correpsodnign to signed prekey and one
            //time prekey A used
            //Using these, B repeats DH and KDF calculations from previous section
            //to derive SK and deletes DH values
            //B then does the AD sequence again
            //finally B decrypts ciphertext using SK and AD. If fails, abort protocol
            //If it does decrypt correctly, then B deletes one-time prekey pruvate key, then everyone
            //can continue using SK to send messages

            String message1 = "Hello World!";
            String message2 = "World says hello!";
            String encryptedMessage1 = one.encrypt(state1, message1, "");
            String encryptedMessage2 = two.encrypt(state2, message2, "");
            String decryptedMessage1 = two.decrypt(state2, encryptedMessage1, "");
            String decryptedMessage2 = one.decrypt(state1, encryptedMessage2, "");
            Log.i("IDK", "Message1 plain: " + message1);
            Log.i("IDK", "Message2 plain: " + message2);
            Log.i("IDK", "Encrypted message1: " + encryptedMessage1);
            Log.i("IDK", "Encrypted message2: " + encryptedMessage2);
            Log.i("IDK", "Decrypted message1: " + decryptedMessage1);
            Log.i("IDK", "Decrypted message2: " + decryptedMessage2);
        }catch(GeneralSecurityException e){
            Log.i("IDKERROR", e.toString());
        }
         Log.i("IDK", "I'm after try!");
        //KeyFactory factory = KeyFactory.getInstance("EdDSA");
        /*KeyPairGenerator generator = KeyPairGenerator.getInstance("ECDSA");
        generator.initialize(ECNamedCurveTable.getParameterSpec("P-256"));//is this right??
         KeyPair pair = generator.generateKeyPair();

         ECCurve curve = new ECCurve() {
             @Override
             public int getFieldSize() {
                 return 0;
             }

             @Override
             public ECFieldElement fromBigInteger(BigInteger x) {
                 return null;
             }

             @Override
             public boolean isValidFieldElement(BigInteger x) {
                 return false;
             }

             @Override
             protected ECCurve cloneCurve() {
                 return null;
             }

             @Override
             protected ECPoint createRawPoint(ECFieldElement x, ECFieldElement y, boolean withCompression) {
                 return null;
             }

             @Override
             protected ECPoint createRawPoint(ECFieldElement x, ECFieldElement y, ECFieldElement[] zs, boolean withCompression) {
                 return null;
             }

             @Override
             public ECPoint getInfinity() {
                 return null;
             }

             @Override
             protected ECPoint decompressPoint(int yTilde, BigInteger X1) {
                 return null;
             }
         };*/
         //Signature s = Signature.getInstance("SHA256withECDSA");//bouncy castle
         //s.initSign(pair.getPrivate());
         //s.update(plaintext.getBytes());//update does what??
         //s.sign();//byte outBuf, int offset, int len, puts signature in outbuf, or juts
         //normal sign
         //update updates data to be signed or verified
         //verify(byte[] signature) or with offset snd len
         //Signature verify = Signature.getInstance("SHA256withECDSA");
         //verify.initVerify(pair.getPublic());
         //verify.update(plaintext.getBytes());
         //boolean result = verify.verify(signature);

         //initial message it 32 bytes IKA, 32 bytes EKA, 4 bytes for int saying which
         // prekey, and the rest is ciphertext

     }

     //create and verify EdDSA-signatures!!!! XEdDSA signature scheme
    //Ellipctic curve uses montogmery ladder but need twisted edwards
    //XEdDSA signing and verifying requires k (mongomery private key)
    //M (message to sgn(byte seq)), Z (64 bytes of secure random data)
    //output is siganture (R||s) of byte seq of length 2b where R encodes
    //a point and s encodes an integer modulo q
    //SHA-512 used, need hash function that applies hash to input,
    //and returns integer which is output of the hash parsed in little-endian
    //xeddsa_sign(k, M, Z){ Pair<A,a> = calculateKeyPair(k); r = hash(a||M||Z)(mod q)
    //R = rB; h = hash(R||A||M)(mod q); s = r + ha(mod q); return R || s;}
    //xeddsa_verify(u, M, (R||s)){ if u >= p or R.y >= 2^|p| or s >= 2^|q|{ return false}
    //A = convert_mont(u); if not on_curve(A) then return false; h = hash(R||A||M)(mod q);
    //R(check) = sB - hA; if bytes_equal(R, R(check)) then return true; return false;
    //

}