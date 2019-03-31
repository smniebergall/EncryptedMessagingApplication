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
import android.view.View;
import android.widget.Button;
import android.widget.Toast;

import com.firebase.client.Config;
import com.firebase.client.Firebase;
import com.google.android.material.button.MaterialButton;
import com.google.android.material.textfield.TextInputEditText;
import com.google.firebase.database.DatabaseReference;
import com.google.firebase.database.FirebaseDatabase;

import org.apache.commons.lang3.StringUtils;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.*;
import java.util.ArrayList;
import java.util.List;

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
        //try {
            //KeyPairGenerator generator = KeyPairGenerator.getInstance("DiffieHellman");
            /*KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
            generator.initialize(256);
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

        //}catch(NoSuchAlgorithmException e){
            //handle exception
        //}
        //byte[] publicKey = pair.getPublic().getEncoded();
        //B is Base Point, I identoty point, p field prime, q order of base
        //point, c cofactor, d edwards curve constant, A mongomnery
        //curve constant, n nonsquare integer modulo integer, |p| ceil(log2(p)),
        //|q| ceil(log2(q)), b 8*(ceil((|p| +1)/8)
        //on_curve(Point P) returns if P satisfies equation
        //mongomery curve equation for points(u,v)= v^2 = u(u^2 +Au +1)(mod p)
        //elligator2(int r){ u1 = -A * inversion(1 +nr^2)(mod p);
        //w1 = u1(u1^2 +Au1 +1) (mod p); if w1^(p-1)/2 == -1 {
        //u2 = -A -u1 (mod p); return u2;} return u1;}
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
        if(StringUtils.isNotBlank(error.getMessage())){
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

     /*protected Point convertMont(int u){
        Point p;
        //u_masked = u(mod 2^|p|)
         //P.y = u_to_y(u_masked)
         //P.s = 0
         //return P
        return p;
     }*/
     protected int elligator2(int r){
         //u1 = -A * inversion(1 +nr^2)(mod p);
         //w1 = u1(u1^2 +Au1 +1) (mod p); if w1^(p-1)/2 == -1 {
         //u2 = -A -u1 (mod p); return u2;} return u1;}
        return r;
     }
}