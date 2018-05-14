package com.teskalabs.ateska.rsakeypaircrypto;

import android.content.Intent;
import android.graphics.Color;
import android.os.Bundle;
import android.support.v7.app.AppCompatActivity;
import android.util.Base64;
import android.util.Log;
import android.view.View;
import android.widget.EditText;
import android.widget.ProgressBar;
import android.widget.Spinner;
import android.widget.TextView;
import android.widget.Toast;

import java.security.GeneralSecurityException;
import java.util.Calendar;
import java.util.Date;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import javax.crypto.spec.SecretKeySpec;

public class MainActivity extends AppCompatActivity {

	private static final String TAG = MainActivity.class.getName();

	private RSAKeyPair rsaKeyPair;

	private TextView keyStatusTextView = null;
	private EditText inputText = null;
	private TextView encryptedTextView = null;
	private Spinner keysizeSpinner = null;

	private ProgressBar progressBar = null;
	int busy = 0;

	private final ExecutorService es = Executors.newSingleThreadExecutor();

	private static final int REQUEST_CODE_USER_AUTHORIZED = 1;

	@Override
	protected void onCreate(Bundle savedInstanceState) {
		super.onCreate(savedInstanceState);
		setContentView(R.layout.activity_main);

		keyStatusTextView = (TextView) findViewById(R.id.keyStatusTextView);
		inputText = (EditText) findViewById(R.id.inputText);
		encryptedTextView = (TextView) findViewById(R.id.encryptedTextView);
		progressBar = (ProgressBar) findViewById(R.id.progressBar);
		keysizeSpinner = (Spinner) findViewById(R.id.keysizeSpinner);
		keysizeSpinner.setSelection(3); // Default is 2048 RSA key length

		PRNGFixes.apply();

		rsaKeyPair = new RSAKeyPair("RSAKeyPair");

		updateStatus();
	}

	public void onGenerateKeyPair(View v) {

		try {
			rsaKeyPair.discard();
		} catch (GeneralSecurityException e) {
			Log.w(TAG, "Failed to discard a key");
		}
		updateStatus();

		Calendar cal = Calendar.getInstance();
		cal.set(Calendar.MILLISECOND, 0);
		cal.set(Calendar.SECOND, 0);
		cal.set(Calendar.MINUTE, 0);
		cal.set(Calendar.HOUR_OF_DAY, 0);
		final Date valid_from = cal.getTime();
		cal.add(Calendar.YEAR, 200);
		final Date valid_to = cal.getTime();
		final Integer keySize = Integer.parseInt(keysizeSpinner.getSelectedItem().toString());

		UserAuth.unlockCredentials(this);

		es.submit(new Runnable() {
			@Override
			public void run() {
				MainActivity.this.setBusy(true);
				try
				{
					try {
						rsaKeyPair.generate(MainActivity.this, keySize, "CN=test1/O=TeskaLabs Ltd", valid_from, valid_to, 1, true);
					} catch (Exception e) {
						Log.e(TAG, "RSAKeyPair", e);
						makeToast("RSA key pair generation failed :-(");
					}
					updateStatus();
				}
				finally {
					MainActivity.this.setBusy(false);
				}
			}
		});
	}

	public void onDeleteKeyPair(View v) {
		try {
			rsaKeyPair.discard();
		} catch (GeneralSecurityException e) {
			Log.e(TAG, "Failed to discard a key");
			makeToast("Failed to discard a kay");
		}
		updateStatus();
	}

	public void onEncrypt(View v) {

		final byte[] input = inputText.getText().toString().getBytes();

		es.submit(new Runnable() {
			@Override
			public void run() {
				MainActivity.this.setBusy(true);
				try
				{
					byte[] output = rsaKeyPair.encrypt(input);
					updateStatus();

					if (output == null)
					{
						makeToast("Failed to encrypt!");
						return;
					}

					final String encodedOutput = Base64.encodeToString(output, Base64.DEFAULT);
					runOnUiThread(new Runnable() {
						public void run() {
							encryptedTextView.setText(encodedOutput);
						}
					});
				}

				catch (GeneralSecurityException e) {
					Log.e(TAG, "Error when encrypting");
					makeToast("Failed to encrypt!");
				}

				finally {
					MainActivity.this.setBusy(false);
				}
			}
		});
	}

	public void onDecrypt(View v) {
		String encodedInput = encryptedTextView.getText().toString();
		final byte[] input = Base64.decode(encodedInput, Base64.DEFAULT);

		es.submit(new Runnable() {
			@Override
			public void run() {
				MainActivity.this.setBusy(true);
				try {
					byte[] output = rsaKeyPair.decrypt(input);
					if (output == null) {
						makeToast("Decrypt failed!");
						return;
					}
					final String outputString = new String(output);
					makeToast(outputString);
				}
				catch (UserAuth.UserNotAuthenticatedException e) {
					UserAuth.showAuthenticationScreen(MainActivity.this, null, null, REQUEST_CODE_USER_AUTHORIZED);
				}
				catch (GeneralSecurityException e) {
					Log.e(TAG, "Error when decrypting");
					makeToast("Decrypt failed!");
				}
				finally {
					MainActivity.this.setBusy(false);
				}
			}
		});
	}


	public void onDeriveKey(View view) {
		es.submit(new Runnable() {
			@Override
			public void run() {
				MainActivity.this.setBusy(true);
				try {
					byte[] key = rsaKeyPair.derive("test-id", 32);
					SecretKeySpec secretkey = new SecretKeySpec(key, "AES");

					final String encodedOutput = Base64.encodeToString(key, Base64.DEFAULT);
					runOnUiThread(new Runnable() {
						public void run() {
							encryptedTextView.setText(encodedOutput);
						}
					});
				}
				catch (UserAuth.UserNotAuthenticatedException e) {
					UserAuth.showAuthenticationScreen(MainActivity.this, null, null, REQUEST_CODE_USER_AUTHORIZED);
				}
				catch (GeneralSecurityException e) {
					Log.e(TAG, "Error when deriving key", e);
					makeToast("Key derivation failed!");
				}
				catch (Exception e) {
					Log.e(TAG, "Error when deriving key", e);
					makeToast("Key derivation failed!");
				}
				finally {
					MainActivity.this.setBusy(false);
				}
			}
		});
	}

	@Override
	protected void onActivityResult(int requestCode, int resultCode, Intent data)
	{
		if (requestCode == REQUEST_CODE_USER_AUTHORIZED)
		{
			if (resultCode == RESULT_OK) {
				onDecrypt(null);
			}
		}
	}

	protected void makeToast(final String text) {
		runOnUiThread(new Runnable() {
			public void run() {
				Toast.makeText(MainActivity.this, text, Toast.LENGTH_LONG).show();
			}
		});
	}

	synchronized protected void setBusy(boolean isBusy)
	{
		if (isBusy)
		{
			busy += 1;
			if (busy == 1) runOnUiThread(new Runnable() {
				public void run() {
					progressBar.setIndeterminate(true);
				}
			});
		}
		else
		{
			busy -= 1;
			if (busy < 0) busy = 0;
			if (busy == 0) runOnUiThread(new Runnable() {
				public void run() {
					progressBar.setIndeterminate(false);
				}
			});

		}
	}

	protected void updateStatus()
	{
		runOnUiThread(new Runnable() {
			public void run() {
				try {
					if (rsaKeyPair.exists()) {
                        keyStatusTextView.setBackgroundColor(Color.parseColor("#00FF00"));
                    } else {
                        keyStatusTextView.setBackgroundColor(Color.parseColor("#FF0000"));
                    }
				} catch (GeneralSecurityException e) {
					Log.e(TAG, "rsaKeyPair.exists() failed");
					keyStatusTextView.setBackgroundColor(Color.parseColor("#00FFFF"));
				}
			}
		});
	}

}
