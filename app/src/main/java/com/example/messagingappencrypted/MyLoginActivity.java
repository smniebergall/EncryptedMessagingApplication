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
            KeyPairGenerator generator = KeyPairGenerator.getInstance("X25519");//does this actally work
            generator.initialize(256);//what size??
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
            database.child("users").child(ID).setValue(bundle);
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
        try{
            KeyPairGenerator generator = KeyPairGenerator.getInstance("X25519");//does this actally work
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
            String ID = ChatSDK.currentUserID();
            KeyBundle bundle1 = new KeyBundle(priv1, prekey1, prekeys1);
            ActualKeyBundle realBundle1 = new ActualKeyBundle(ID, pair1, actualPrekey1, realPrekeys1);

            KeyPair pair2 = generator.generateKeyPair();
            Key priv2 = pair1.getPrivate();
            Key pub2 = pair1.getPublic();
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
            String ID2 = ChatSDK.currentUserID();
            KeyBundle bundle2 = new KeyBundle(priv2, prekey2, prekeys2);
            ActualKeyBundle realBundle2 = new ActualKeyBundle(ID2, pair2, actualPrekey2, realPrekeys2);

            State state1 = new State();
            State state2 = new State();
            User one = new User(ID);
            User two = new User(ID2);
            //key agreement protocol here!!
            Key secret = null;
            Key pub = null;
            KeyPair priv = null;
            Key sharedHeaderKeySelf = null;
            Key sharedNextHeaderOther = null;
            Key sharedHeaderKeyOther = null;
            Key nextHeaderSelf = null;
            one.updateUserForRatchetStart(state1, secret, pub, sharedHeaderKeySelf, sharedNextHeaderOther);
            two.updateUserFOrRatchetSecond(state2, secret, priv, sharedHeaderKeyOther, nextHeaderSelf);

            String message1 = "Hello World!";
            String message2 = "World says hello!";
            String encryptedMessage1 = one.encrypt(state1, message1, "");
            String encryptedMessage2 = two.encrypt(state2, message2, "");
            String decryptedMessage1 = two.decrypt(state2, encryptedMessage1, "");
            String decryptedMessage2 = one.decrypt(state1, encryptedMessage2, "");
        }catch(GeneralSecurityException e){

        }

     }
     /*protected Point convertMont(int u){
        Point p;
        //u_masked = u(mod 2^|p|)
         //P.y = u_to_y(u_masked)
         //P.s = 0
         //return P
        return p;
     }*/

}