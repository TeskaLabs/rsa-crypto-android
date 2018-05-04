package com.teskalabs.ateska.rsakeypaircrypto;

import android.annotation.TargetApi;
import android.app.Activity;
import android.app.KeyguardManager;
import android.content.ActivityNotFoundException;
import android.content.Context;
import android.content.Intent;
import android.os.Build;
import android.util.Log;

public class UserAuth {

    private static final String TAG = UserAuth.class.getName();

    public static void unlockCredentials(Context context) {
        // For this part, make sure that you called following code:
        try {
            if (Build.VERSION.SDK_INT < Build.VERSION_CODES.HONEYCOMB) {
                context.startActivity(new Intent("android.credentials.UNLOCK"));
            } else {
                context.startActivity(new Intent("com.android.credentials.UNLOCK"));
            }
        } catch (ActivityNotFoundException e) {
            Log.e(TAG, "No UNLOCK activity: " + e.getMessage(), e);
        }
    }

    @TargetApi(Build.VERSION_CODES.LOLLIPOP)
    public static void showAuthenticationScreen(Activity activity, CharSequence title, CharSequence description, int requestCode)
    {
        KeyguardManager mKeyguardManager = (KeyguardManager) activity.getSystemService(Context.KEYGUARD_SERVICE);

        // Create the Confirm Credentials screen. You can customize the title and description. Or
        // we will provide a generic one for you if you leave it null
        Intent intent = mKeyguardManager.createConfirmDeviceCredentialIntent(title, description);
        if (intent != null) {
            activity.startActivityForResult(intent, requestCode);
        }
    }

    public static class UserNotAuthenticatedException extends Exception
    {
        public UserNotAuthenticatedException() { super(); }

        public UserNotAuthenticatedException(Throwable e) { super(e); }

        public UserNotAuthenticatedException(String message) {
            super(message);
        }

        public UserNotAuthenticatedException(String message, Throwable cause) { super(message, cause); }
    }

}
