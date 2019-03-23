package com.example.messagingappencrypted;

import android.content.Context;
import android.content.Intent;

import androidx.annotation.NonNull;
import androidx.appcompat.app.AppCompatActivity;
import android.os.Bundle;
import android.util.Log;
import android.view.View;
import android.widget.EditText;
import android.widget.Toast;
import android.os.Bundle;

import com.google.android.gms.tasks.OnCompleteListener;
import com.google.android.gms.tasks.Task;
import com.google.firebase.auth.AuthResult;
import com.google.firebase.auth.FirebaseAuth;
import com.google.firebase.auth.FirebaseUser;

import co.chatsdk.core.base.BaseNetworkAdapter;
import co.chatsdk.core.dao.Keys;
import co.chatsdk.core.dao.Message;
import co.chatsdk.core.dao.User;
import co.chatsdk.core.error.ChatSDKException;
import co.chatsdk.core.session.ChatSDK;
import co.chatsdk.core.session.Configuration;
import co.chatsdk.core.session.InterfaceManager;
import co.chatsdk.core.types.AccountDetails;
import co.chatsdk.core.types.ChatError;
import co.chatsdk.firebase.FirebaseModule;
import co.chatsdk.firebase.FirebaseNetworkAdapter;
import co.chatsdk.firebase.file_storage.FirebaseFileStorageModule;
import co.chatsdk.firebase.push.FirebasePushModule;
import co.chatsdk.ui.chat.ChatActivity;
import co.chatsdk.ui.manager.BaseInterfaceAdapter;
import co.chatsdk.core.session.StorageManager;
import co.chatsdk.ui.manager.UserInterfaceModule;
import co.chatsdk.ui.profile.ProfileActivity;

//implements View.OnClickListener
public class MainActivity extends AppCompatActivity {
    public static final String EXTRA_MESSAGE = "com.example.encryptedmessageapp.MESSAGE";
    private FirebaseAuth auth;
    //private EditText passwordText;
    private Context context;
    //private EditText emailText;
    /*private static final String TAG = "EmailPassword";*/
    //private Message message = StorageManager.shared().createEntity(Message.class);
    private User user; //StorageManager.shared().createEntity(User.class);
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        /*emailText = findViewById(R.id.email_text);
        passwordText = findViewById(R.id.password_text);
        findViewById(R.id.loginButton).setOnClickListener(this);
        findViewById(R.id.register_button).setOnClickListener(this);*/
        auth = FirebaseAuth.getInstance();
        context = getApplicationContext();
        Configuration.Builder builder = new Configuration.Builder(context);
        builder.firebaseRootPath("prod");
        UserInterfaceModule.activate(context);
        FirebaseModule.activate();
        try{
            ChatSDK.initialize(builder.build(), new FirebaseNetworkAdapter(), new BaseInterfaceAdapter(context));
            builder.facebookLoginEnabled(false);
            builder.twitterLoginEnabled(false);
        }
        catch(ChatSDKException e){

        }
        FirebaseFileStorageModule.activate();
        FirebasePushModule.activate();
        user = StorageManager.shared().createEntity(User.class);
        //InterfaceManager.shared().a.startMainActivity(context);
        
        InterfaceManager.shared().a.startLoginActivity(context, true);
    }
    @Override
    public void onStart(){
        super.onStart();
        /*FirebaseUser currentUser = auth.getCurrentUser();
        updateUI(currentUser);*/
    }
    /*@Override
    public void onClick(View v){
        int button = v.getId();
        if(button == R.id.loginButton){
            signInUser(emailText.getText().toString(), passwordText.getText().toString());
        }
        else if(button == R.id.register_button){
            createUserAccount(emailText.getText().toString(), passwordText.getText().toString());
        }
        else if(button == R.id.logout_Button){
            signOut();
        }
        else if(button == R.id.profile_button){
            startProfile();
        }
        else if(button == R.id.contacts_button){
            startContacts();
        }
        else if(button == R.id.messages_button){
            showMessages();
        }*/
        /*else if(button == R.id.startChatButton){
            startChat();
        }*/
    }
    /*private void createUserAccount(String email, String password){
        Log.d(TAG, "createAccount:"+ email);
        AccountDetails details = AccountDetails.signUp(email, password);
        ChatSDK.auth().authenticate(details).subscribe();
        ChatSDK.auth().authenticateWithCachedToken().subscribe();

        auth.createUserWithEmailAndPassword(email, password).addOnCompleteListener(this, new OnCompleteListener<AuthResult>() {
            @Override
            public void onComplete(@NonNull Task<AuthResult> task) {
                if(task.isSuccessful()){
                    Log.d(TAG, "createUserWithEmail:success");
                    FirebaseUser user = auth.getCurrentUser();
                    updateUI(user);

                }
                else {
                    Log.w(TAG, "createUserWithEmail:failure", task.getException());
                    Toast.makeText(MainActivity.this, "Authentication failed.", Toast.LENGTH_SHORT).show();
                    updateUI(null);
                }
            }
        });
        //* do error checking eventually with .catch
    }

    private void signInUser(String email, String password){
        Log.d(TAG, "signIn:" + email);
        AccountDetails details = AccountDetails.username(email, password);
        ChatSDK.auth().authenticate(details).subscribe();
        ChatSDK.auth().authenticateWithCachedToken().subscribe();
        auth.signInWithEmailAndPassword(email, password).addOnCompleteListener(this, new OnCompleteListener<AuthResult>() {
            @Override
            public void onComplete(@NonNull Task<AuthResult> task) {
                if(task.isSuccessful()){
                    Log.d(TAG, "signInWithEmail:success");
                    FirebaseUser user = auth.getCurrentUser();
                    updateUI(user);
                }
                else {
                    Log.w(TAG, "signInWithEMail:failure", task.getException());
                    Toast.makeText(MainActivity.this, "Authentication failed.", Toast.LENGTH_SHORT).show();
                    updateUI(null);
                }
            }
        });
    }*/

    /*private void signOut(){
        auth.signOut();
        ChatSDK.auth().logout().subscribe();
        updateUI(null);
    }

    //* Validate if email and password are even correct or valid inputs, email verification?
    private void updateUI(FirebaseUser user){
        if( user != null){
            findViewById(R.id.register_button).setVisibility(View.GONE);
            findViewById(R.id.loginButton).setVisibility(View.GONE);
            findViewById(R.id.email_text).setVisibility(View.GONE);
            findViewById(R.id.password_text).setVisibility(View.GONE);
            findViewById(R.id.password_text_view).setVisibility(View.GONE);
            findViewById(R.id.email_text_view).setVisibility(View.GONE);
            findViewById(R.id.logout_Button).setVisibility(View.VISIBLE);
            //findViewById(R.id.profile_button).setVisibility(View.VISIBLE);
            //findViewById(R.id.contacts_button).setVisibility(View.VISIBLE);
            //findViewById(R.id.messages_button).setVisibility(View.VISIBLE);
            //InterfaceManager.shared().a.startMainActivity(context);
            //findViewById(R.id.startChatButton).setVisibility(View.VISIBLE);
        }
        else {
            findViewById(R.id.register_button).setVisibility(View.VISIBLE);
            findViewById(R.id.loginButton).setVisibility(View.VISIBLE);
            findViewById(R.id.email_text).setVisibility(View.VISIBLE);
            findViewById(R.id.password_text).setVisibility(View.VISIBLE);
            findViewById(R.id.password_text_view).setVisibility(View.VISIBLE);
            findViewById(R.id.email_text_view).setVisibility(View.VISIBLE);
            findViewById(R.id.logout_Button).setVisibility(View.GONE);
            findViewById(R.id.profile_button).setVisibility(View.GONE);
            findViewById(R.id.contacts_button).setVisibility(View.GONE);
            findViewById(R.id.messages_button).setVisibility(View.GONE);
            //findViewById(R.id.startChatButton).setVisibility(View.GONE);
        }//make
    }
    private void startProfile(){
        Intent intent = new Intent(this, ProfileActivity.class);
        intent.putExtra(Keys.UserId, user.getEntityID());
        startActivity(intent);
    }
    private void startContacts(){
        //InterfaceManager.shared().a.start;
    }
    private void showMessages(){
        Intent intent = new Intent(this, ChatActivity.class);
        //intent.putExtra();
        startActivity(intent);
        //InterfaceManager.shared().a.start;
    }*/
   /* private void startChat(){
        Intent intent = new Intent(this, ChatActivity.class);
        startActivity(intent);
    }*/
}
//instead of start chat button, start activity for main screen with all conversations and seeing profile.
//profile, edit profile, add contacts, chatting...

