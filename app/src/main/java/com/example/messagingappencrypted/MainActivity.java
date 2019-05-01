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

import com.fasterxml.jackson.databind.ser.Serializers;
import com.google.android.gms.tasks.OnCompleteListener;
import com.google.android.gms.tasks.Task;
import com.google.firebase.auth.AuthResult;
import com.google.firebase.auth.FirebaseAuth;
import com.google.firebase.auth.FirebaseUser;

import java.security.Provider;
import java.security.Security;
import java.util.Set;

import co.chatsdk.core.base.BaseNetworkAdapter;
import co.chatsdk.core.dao.Keys;
import co.chatsdk.core.dao.Message;
import co.chatsdk.core.dao.User;
import co.chatsdk.core.error.ChatSDKException;
import co.chatsdk.core.interfaces.InterfaceAdapter;
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
import co.chatsdk.ui.main.BaseActivity;
import co.chatsdk.ui.manager.BaseInterfaceAdapter;
import co.chatsdk.core.session.StorageManager;
import co.chatsdk.ui.manager.UserInterfaceModule;
import co.chatsdk.ui.profile.ProfileActivity;

//implements View.OnClickListener
public class MainActivity extends AppCompatActivity {
//AppCompatActivity
    //normally extends AppCompatActivity
    //public static final String EXTRA_MESSAGE = "com.example.encryptedmessageapp.MESSAGE";
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
        passwordText = findViewById(R.id.password_text);*/
        /*findViewById(R.id.loginButton).setOnClickListener(this);
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

        ChatSDK.shared().setInterfaceAdapter(new MyInterfaceAdapter(context));


        ChatSDK.ui().startLoginActivity(context, true);
        ChatSDK.ui().startMainActivity(context);
        /*Provider[] providers = Security.getProviders();
         for(Provider provider : providers){
             boolean printedProvider = false;
             Set<Provider.Service> services = provider.getServices();
             for(Provider.Service service : services){
                 String algorithm = service.getAlgorithm();
                 String type = service.getType();
                     System.out.printf("%n === %s ===%n%n", provider.getName());
                     System.out.printf("Type: %s alg: %s%n", type, algorithm);
             }
         }*/
        //InterfaceManager.shared().a.startMainActivity(context);

    }
    @Override
    public void onStart(){
        super.onStart();
        ChatSDK.ui().startLoginActivity(context, true);
        ChatSDK.ui().startMainActivity(context);
        /*Provider[] providers = Security.getProviders();
        for(Provider provider : providers){
            boolean printedProvider = false;
            Set<Provider.Service> services = provider.getServices();
            for(Provider.Service service : services){
                String algorithm = service.getAlgorithm();
                String type = service.getType();
                if(type.equalsIgnoreCase("SecretKey")){
                    System.out.printf("%n === %s ===%n%n", provider.getName());
                    System.out.printf("Type: %s alg: %s%n", type, algorithm);
                }

            }
        }*/
        //ChatSDK.ui().startLoginActivity(context, true);
        //InterfaceManager.shared().a.startLoginActivity(context, true);
        //InterfaceManager.shared().a.startMainActivity(context);
        //InterfaceManager.shared().a.startLoginActivity(context);
        //FirebaseUser currentUser = auth.getCurrentUser();
        //updateUI(currentUser);
    }


}
//instead of start chat button, start activity for main screen with all conversations and seeing profile.
//profile, edit profile, add contacts, chatting...

