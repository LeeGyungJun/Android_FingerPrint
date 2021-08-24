package com.example.myapplication2;

import android.annotation.TargetApi;
import android.hardware.fingerprint.FingerprintManager;
import android.os.Build;
import android.os.Bundle;
import androidx.appcompat.app.AppCompatActivity;

@TargetApi(Build.VERSION_CODES.N)
public class MainActivity extends AppCompatActivity {

    private FingerprintManager.CryptoObject mCryptoObject;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
    }

    @Override
    protected void onResume() {
        super.onResume();

        FingerPrintHandler fp = new FingerPrintHandler(this);
        fp.Authenticate();
    }

}