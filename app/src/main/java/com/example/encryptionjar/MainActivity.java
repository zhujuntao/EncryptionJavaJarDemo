package com.example.encryptionjar;

import android.support.v7.app.AppCompatActivity;
import android.os.Bundle;
import android.util.Log;

import com.example.encryptionjarlibrary.utils.DESUtils;

public class MainActivity extends AppCompatActivity {

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        String num="13512345678";
        Log.d("main","=========="+num);
        Log.d("main","=====des====="+ DESUtils.encodeV4(num));

    }
}
