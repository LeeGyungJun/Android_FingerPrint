package com.example.myapplication2;

import android.Manifest;
import android.annotation.TargetApi;
import android.app.KeyguardManager;
import android.content.Context;
import android.content.pm.PackageManager;
import android.hardware.fingerprint.FingerprintManager;
import android.os.Build;
import android.os.CancellationSignal;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.util.Log;
import android.widget.Toast;

import androidx.annotation.RequiresApi;
import androidx.core.app.ActivityCompat;

import java.io.IOException;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.util.List;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

import static android.content.Context.FINGERPRINT_SERVICE;
import static android.content.Context.KEYGUARD_SERVICE;

@TargetApi(Build.VERSION_CODES.N)
public class FingerPrintHandler extends FingerprintManager.AuthenticationCallback {

    private CancellationSignal cancellationSignal;
    private Context appContext;

    private FingerprintManager fingerprintManager;
    private KeyguardManager keyguardManager;
    private KeyGenerator keyGenerator;
    private static final String KEY_NAME = "example_key";

    private FingerprintManager.CryptoObject mCryptoObject;
    private CancellationSignal mCancellationSignal;
    private boolean mSelfCancelled;


    public FingerPrintHandler(Context context) {
        appContext = context;
    }

    @RequiresApi(api = Build.VERSION_CODES.N)
    public void Authenticate() {

        try {
            if (getSecretKey() == null) {
                Log.d("my", "getSecretKey 이 없음 ====================");
                generateSecretKey(new KeyGenParameterSpec.Builder(KEY_NAME, KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
                        .setBlockModes(KeyProperties.BLOCK_MODE_CBC)
                        .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_PKCS7)
                        .setUserAuthenticationRequired(true)
                        .setInvalidatedByBiometricEnrollment(true)
                        .build());
            }else{
                Log.d("my", "getSecretKey 이 있음 ====================");
            }
        } catch (Exception e) {
            e.printStackTrace();
        }

        try {
            Cipher cipher = getCipher();
            SecretKey secretKey = getSecretKey();
            cipher.init(Cipher.ENCRYPT_MODE, secretKey);

            if (canAuth()) {
                startAuth(fingerprintManager, new FingerprintManager.CryptoObject(cipher));
            }
        } catch (InvalidKeyException | UnrecoverableKeyException e) {
            Log.e("my","InvalidKey!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!");
            e.printStackTrace();
        } catch (Exception e) {
            e.printStackTrace();
        }

        //Toast.makeText(appContext,"손구락 개수 : " + getFingerprintInfo(appContext),Toast.LENGTH_SHORT).show();
    }

    private boolean canAuth() {

        boolean flag = true;

        keyguardManager = (KeyguardManager) appContext.getSystemService(KEYGUARD_SERVICE);
        fingerprintManager = (FingerprintManager) appContext.getSystemService(FINGERPRINT_SERVICE);

        if (!keyguardManager.isKeyguardSecure()) {
            Toast.makeText(appContext,"Lock screen security not enabled in Settings",Toast.LENGTH_LONG).show();
            flag = false;
        }

        if (ActivityCompat.checkSelfPermission(appContext,Manifest.permission.USE_FINGERPRINT) !=PackageManager.PERMISSION_GRANTED) {
            Toast.makeText(appContext,"Fingerprint authentication permission not enabled",Toast.LENGTH_LONG).show();
            flag = false;
        }

        if (!fingerprintManager.hasEnrolledFingerprints()) {
            // This happens when no fingerprints are registered.
            Toast.makeText(appContext,"Register at least one fingerprint in Settings",Toast.LENGTH_LONG).show();
            flag = false;
        }

        return flag;

    }

    //키 생성
    private void generateSecretKey(KeyGenParameterSpec keyGenParameterSpec) throws Exception {
        if (android.os.Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
            KeyGenerator keyGenerator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore");
            keyGenerator.init(keyGenParameterSpec);
            keyGenerator.generateKey();
        }
    }

    // 키 스토어에 등록된 키를 가져오는 함수
    public SecretKey getSecretKey() throws Exception {
        KeyStore keyStore = KeyStore.getInstance("AndroidKeyStore");

        // keyStore에 액세스하려면 먼저 로드해야한다.
        keyStore.load(null);
        return (SecretKey)keyStore.getKey(KEY_NAME, null);
    }

    //암호화
    public Cipher getCipher() throws Exception {
        return Cipher.getInstance(KeyProperties.KEY_ALGORITHM_AES + "/" + KeyProperties.BLOCK_MODE_CBC + "/" + KeyProperties.ENCRYPTION_PADDING_PKCS7);
    }

    /*
    * @param1 fingerprintManager
    * @param2 cryptoObject
     */
    public void startAuth(FingerprintManager manager, FingerprintManager.CryptoObject cryptoObject) {

        if (ActivityCompat.checkSelfPermission(appContext,Manifest.permission.USE_FINGERPRINT) != PackageManager.PERMISSION_GRANTED) {
            return;
        }
        manager.authenticate(cryptoObject, cancellationSignal, 0, this, null);
    }

    @Override
    public void onAuthenticationError(int errMsgId, CharSequence errString) {
        Toast.makeText(appContext,"Authentication error\n" + errString,Toast.LENGTH_LONG).show();
    }

    @Override
    public void onAuthenticationHelp(int helpMsgId, CharSequence helpString) {
        Toast.makeText(appContext,"Authentication help\n" + helpString,Toast.LENGTH_LONG).show();
    }

    @Override
    public void onAuthenticationFailed() {
        Toast.makeText(appContext,"Authentication failed.",Toast.LENGTH_LONG).show();
    }

    @Override
    public void onAuthenticationSucceeded(FingerprintManager.AuthenticationResult result) {
        Toast.makeText(appContext,"Authentication succeeded.",Toast.LENGTH_LONG).show();
    }



    public boolean isFingerprintAuthAvailable() {
        // The line below prevents the false positive inspection from Android Studio
        // noinspection ResourceType
        return fingerprintManager.isHardwareDetected() && fingerprintManager.hasEnrolledFingerprints();
    }

    public void startListening(FingerprintManager.CryptoObject cryptoObject) {
        if (!isFingerprintAuthAvailable()) {
            return;
        }
        mCancellationSignal = new CancellationSignal();
        mSelfCancelled = false;
        // The line below prevents the false positive inspection from Android Studio
        // noinspection ResourceType
        fingerprintManager.authenticate(cryptoObject, mCancellationSignal, 0 /* flags */, this, null);
        //mIcon.setImageResource(R.drawable.ic_fp_40px);
    }

    public void stopListening() {
        if (mCancellationSignal != null) {
            mSelfCancelled = true;
            mCancellationSignal.cancel();
            mCancellationSignal = null;
        }
    }

    public void setCryptoObject(FingerprintManager.CryptoObject cryptoObject) {
        mCryptoObject = cryptoObject;
    }






    //손구락 갯수 판단
    private int getFingerprintInfo(Context context) {
        Object obj = null;
        try {
            FingerprintManager fingerprintManager = (FingerprintManager) context.getSystemService(FINGERPRINT_SERVICE);
            Method method = FingerprintManager.class.getDeclaredMethod("getEnrolledFingerprints");
            obj = method.invoke(fingerprintManager);

            if (obj != null) {
                Class<?> clazz = Class.forName("android.hardware.fingerprint.Fingerprint");
                Method getFingerId = clazz.getDeclaredMethod("getFingerId");

                for (int i = 0; i < ((List) obj).size(); i++) {
                    Object item = ((List) obj).get(i);
                    if(item != null) {
                        System.out.println("fkie4. fingerId: " + getFingerId.invoke(item));
                    }
                }
            }
        } catch (NoSuchMethodException | IllegalAccessException | ClassNotFoundException | InvocationTargetException e) {
            e.printStackTrace();
        }
        return ((List) obj).size();
    }

}