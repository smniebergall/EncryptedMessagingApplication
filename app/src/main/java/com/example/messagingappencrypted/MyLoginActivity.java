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
import android.security.keystore.KeyGenParameterSpec;
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

import org.spongycastle.asn1.x509.SubjectPublicKeyInfo;
import org.spongycastle.asn1.x9.X9ECParameters;
import org.spongycastle.crypto.ec.CustomNamedCurves;
import org.spongycastle.jcajce.provider.asymmetric.ec.KeyFactorySpi;
import org.spongycastle.jcajce.provider.asymmetric.util.EC5Util;
import org.spongycastle.jcajce.provider.symmetric.AES;
import org.spongycastle.jce.ECNamedCurveTable;
import org.spongycastle.jce.spec.ECNamedCurveGenParameterSpec;
import org.spongycastle.jce.spec.ECNamedCurveParameterSpec;
import org.spongycastle.jce.spec.ECNamedCurveSpec;
import org.spongycastle.math.ec.ECCurve;
import org.spongycastle.math.ec.ECFieldElement;
import org.spongycastle.math.ec.custom.djb.Curve25519;

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.*;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Set;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.KeyGenerator;
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
        /*for(Provider provider : Security.getProviders()){
            System.out.println(provider);
            for(Provider.Service service : provider.getServices()){
                if("ECGenParameterSpec".equalsIgnoreCase(service.getType())){
                    System.out.println(service);
                }
            }
        }*/
        //Security.getProviders("AlgorithmParameters.EC")[0].getService("AlgorithmParameters","EC").getAttribute("SUppostedCurves");

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
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");//does this actally work

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
            KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
            Log.i("IDK", "IN try!!");
            generator.initialize(new ECGenParameterSpec("secp256r1"));//256//nist p-256//x9.62 prime256v1
            String ID = "one";
            String ID2 = "two";
            User one = new User(ID);
            User two = new User(ID2);
            KeyPair pair1 = generator.generateKeyPair();
            ECPublicKey pub1 = (ECPublicKey) pair1.getPublic();
            ECPrivateKey priv1 = (ECPrivateKey) pair1.getPrivate();
            byte[] pub1Bytes = one.k.encodePub(pub1);
            byte[] priv1Bytes = one.k.encodePriv(priv1);
            Log.i("IDK","pub1Bytes length: " + pub1Bytes.length);//65//maybe git rid of first byte?? length-1 means last bte is at index 64 0-31, 32-64, 65
            Log.i("IDK", "pair private length: " + priv1Bytes.length);//32
            List<KeyPair> realPrekeys1 = new ArrayList<KeyPair>();
            for(int i = 0; i < 10; i++){
                realPrekeys1.add(generator.generateKeyPair());
            }
            List<Key> prekeys1 = new ArrayList<Key>();
            for(int i = 0; i < realPrekeys1.size();i++){
                prekeys1.add(realPrekeys1.get(i).getPublic());
            }
            KeyPair actualPrekey1 = generator.generateKeyPair();
            byte[] pubBytes = one.k.encodePub(actualPrekey1.getPublic());
            //byte[] pubBytesX = Arrays.copyOfRange(pubBytes,0, 32);
            Log.i("IDK","actualPrekey1 public length: " + pubBytes.length);
            Log.i("IDK","actualPrekey1 private length: " + one.k.encodePriv((ECPrivateKey) actualPrekey1.getPrivate()).length);
            Key prekey1 = actualPrekey1.getPublic();
            Log.i("IDK", "IN try!! Prekeys done!");
            /*//String ID = ChatSDK.currentUserID();
            //String ID2 = ChatSDK.currentUserID();
            //thinks the above two are still active and not commented out??*/

            Log.i("IDK", "IN try!! Created users!");
            byte[] signedPrekey1 = new byte[32];
            signedPrekey1 = one.signPreKey(pair1, one.k.encodePub(prekey1));//change

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
            byte[] signedPrekey2 = two.signPreKey(pair2, prekey2.getEncoded());//so this is the signature, and the bytes version
            //so in the bundle
            Log.i("IDK", "signedPrekey2: " + signedPrekey2);
            Log.i("IDK", "signedPrekey2 length: " + signedPrekey2.length);
            Log.i("IDK", "IN try!! Signed Prekeys for user 2 and finished prekeys and prekey signature for 2!");
            State state1 = new State();
            State state2 = new State();
            Log.i("IDK", "IN try!! States!");

            KeyBundle bundle2 = new KeyBundle(pub2, prekey2, signedPrekey2, prekeys2);
            ActualKeyBundle realBundle2 = new ActualKeyBundle(ID2, pair2, actualPrekey2, realPrekeys2);
            two.updateKeyBundle(realBundle2);
            Log.i("IDK", "IN try!! Finished all bundles");

            //key agreement protocol here!!
            //did i ever put bundles in the user??
            //Key IdentityOtherPub, Key SignedPreKeyOtherPub, Key signatureOfPreKeyOtherPub, Key oneTimePreKeyOtherpub
            Log.i("IDK", "IN try!! bundle 2 identity: " + bundle2.identity);
            Log.i("IDK", "IN try!! bundle 2 signedPrekey: " + bundle2.prekey);//this now says null??
            Log.i("IDK", "IN try!! bundle 2 signedPrekEy bytes: " + bundle2.signedPreKeyBytes);
            Log.i("IDK", "IN try!! bundle 2 one-time prkeey: " + bundle2.pickPrekeyToSend());
            Log.i("IDK", "IN try!! bundle 1 identity pub: " + realBundle1.identity.getPublic());
            Log.i("IDK", "IN try!! bundle 1 identity priv: " + realBundle1.identity.getPrivate());
            Key secret = one.calculateSecretKey(bundle2.identity, bundle2.prekey, bundle2.signedPreKeyBytes, bundle2.pickPrekeyToSend());
            Log.i("IDK", "Secret key from alice: " + secret.toString());
            byte[] identity1first32 = Arrays.copyOfRange(bundle1.identity.getEncoded(), 0, 32);
            byte[] identity2first32 = Arrays.copyOfRange(bundle2.identity.getEncoded(), 0, 32);
            byte[] AD = one.k.concat(identity1first32, identity2first32);//should be 64
            Log.i("IDK", "AD for alice is: " + AD);
            Log.i("IDK", "AD for alice length is: " + AD.length);
            int[] identifiers = new int[4];
            identifiers[0] = 1;
            identifiers[1] = 1;
            identifiers[2] = 0;
            identifiers[3] = 0;
            byte[] text = "Let's create a ses".getBytes();
            Log.i("IDK", "text length :" + text.length);
            byte[] ciphertext = one.encryptInitialMessage(secret, text, AD);//whole thing is 208 which is devisible by 16
            Log.i("IDK", "ciphertext of intitial message: "+ ciphertext);//signedPrekeys are length 71, so maybe try changing those to the same??
            byte[] initialMessageFromAlice = one.k.initialMessage(bundle1.identity, bundle2.identity, one.ephemeral.getPublic(), identifiers, ciphertext);
            Log.i("IDK", "inititial message from alice: " + initialMessageFromAlice);
            Log.i("IDK", "InitialMessageFromALice length: " + initialMessageFromAlice.length);//254??
            //cipertext is 64
            //each key should be 32??
            //byte[] initialMessage = new byte[initialMessageFromAlice.length-71];
            byte[] ciphertextFromAlice = new byte[ciphertext.length];
            byte[] decryptedInitialMessage = new byte[65];
            byte[] IKAForB = new byte[32];
            byte[] EKAForB = new byte[32];
            byte[] ids = new byte[16];//changed to 8
            int id;
            int id2;
            for(int i = 0; i < 32; i++){
                IKAForB[i] = initialMessageFromAlice[i];
            }
            Log.i("IDK", "IKAforB: " + IKAForB);
            for(int i = 32; i < 64; i++){//changed these
                EKAForB[i-32] = initialMessageFromAlice[i];
            }
            Log.i("IDK", "EKAForB: " + EKAForB);
            for(int i = 64; i < 72; i++){
                ids[i-64] = initialMessageFromAlice[i];//I was assuming 1 int, but seems like two ints?
            }
            //int stuff = initialMessageFromAlice.length-32-32-8;
            //Log.i("IDK", "InitialMessageLength - 32-32-8: "+ stuff);
            for(int i = 80; i < initialMessageFromAlice.length; i++){//changed to 105 not result.lenth
                ciphertextFromAlice[i-80] = initialMessageFromAlice[i];//this is all the secret and AD and text
            }
            byte[] ids1 = new byte[4];
            byte[] ids2 = new byte[4];
            for(int i = 0; i < 4; i++){
                ids1[i] = ids[i];
            }
            for(int i = 4; i < 8; i++){
                ids2[i-4] = ids[i];
            }
            id2 = ByteBuffer.wrap(ids2).getInt();
            Log.i("IDK", "id2: " + id2);
            id = ByteBuffer.wrap(ids1).getInt();
            Key secret2 = two.calculateSecretKey(bundle1.identity, bundle1.prekey, bundle1.getSignedPreKey().getEncoded(), bundle1.getSpecificPreKey(0));//do i actually need identity from message or just use
            byte[] actualCiphertextWithAD = Arrays.copyOfRange(ciphertextFromAlice, 32, ciphertextFromAlice.length);
            byte[] actualCiphertext = Arrays.copyOfRange(actualCiphertextWithAD, 0, ciphertextFromAlice.length-64);//how big is AD
            //ids are not working need to chnage this, for now hard code in 0
            //bundle identity??
            Log.i("IDK", "secret2: " + secret2);
            byte[] AD2 =  two.k.concat(bundle1.identity.getEncoded(), bundle2.identity.getEncoded());
            Log.i("IDK", "AD for Bob: " + AD2);
            decryptedInitialMessage = two.decryptInitialMessage(secret2, ciphertextFromAlice, AD2);
            Log.i("IDK", "Initial Message in string: " + decryptedInitialMessage.toString());

            //delete any prekey used
            Key pub = bundle2.identity;
            KeyPair priv = realBundle2.identity;
            Key sharedHeaderKey = one.findState(state1).headerSending;
            Key sharedNextHeaderKey = two.findState(state2).nextHeaderReceiving;

            one.updateUserForRatchetStart(state1, secret, pub, sharedHeaderKey, sharedNextHeaderKey);
            two.updateUserFOrRatchetSecond(state2, secret, priv, sharedHeaderKey, sharedNextHeaderKey);

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

     }
}