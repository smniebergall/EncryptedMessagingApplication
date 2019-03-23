package com.example.messagingappencrypted;

import android.content.Context;

import co.chatsdk.ui.manager.BaseInterfaceAdapter;

public class MyInterfaceAdapter extends BaseInterfaceAdapter {
    public MyInterfaceAdapter(Context context){
        super(context);
    }
    @Override
    public Class getLoginActivity() {
        return MyLoginActivity.class;
        //need to add cryptography portion to this class
    }

    //probably need private threads encrypted fragment that extends
    //ThreadsFragment
    //co.chatsdk.core.interfaces.ThreadType for private encrypted and
    //potentially public encrypted....is public group?
    //private group and public group and private1to1
    //chat options handler might need new one
    //message handler
    //message display handler
    //chat options??
    //start chat activity for id includes context anf thread entity id
    //private threads tab
    //setPrivateThreadsFragment in Interface Adaptor
}
