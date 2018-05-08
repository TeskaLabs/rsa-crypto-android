package com.teskalabs.ateska.rsakeypaircrypto;

import android.annotation.TargetApi;
import android.content.Context;
import android.os.Build;
import android.security.KeyPairGeneratorSpec;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.security.keystore.UserNotAuthenticatedException;
import android.util.Log;

import java.io.IOException;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.util.Date;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.security.auth.x500.X500Principal;


public class RSAKeyPair {

    private static final String TAG = RSAKeyPair.class.getName();
    private final String alias;


    public RSAKeyPair(String alias) {
        this.alias = alias;
    }


    public boolean exists() throws GeneralSecurityException {
        KeyStore keyStore = obtainKeyStore();
        PrivateKey privateKey = (PrivateKey) keyStore.getKey(alias, null);
        if (privateKey == null) return false;
        return true;
    }


    public void discard() throws GeneralSecurityException {
        KeyStore keyStore = obtainKeyStore();
        keyStore.deleteEntry(alias);
    }


    public byte[] decrypt(byte[] input) throws UserAuth.UserNotAuthenticatedException, GeneralSecurityException {
        KeyStore keyStore = obtainKeyStore();
        PrivateKey privateKey = (PrivateKey) keyStore.getKey(alias, null);
        if (privateKey == null) return null; // No key pair

        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        try {
            return cipher.doFinal(input);
        } catch (GeneralSecurityException e) {

            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                if (e instanceof UserNotAuthenticatedException)
                {
                    Log.w(TAG, "User not logged in!");
                    throw new UserAuth.UserNotAuthenticatedException(e);
                }
            }

            throw e;
        }
    }


    public byte[] encrypt(byte[] input) throws GeneralSecurityException {
        KeyStore keyStore = obtainKeyStore();
        PublicKey publicKey = keyStore.getCertificate(alias).getPublicKey();
        if (publicKey == null) return null; // No key pair

        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        return cipher.doFinal(input);
    }


    public byte[] derive(String keyId, int outLengthBytes) throws UserAuth.UserNotAuthenticatedException, GeneralSecurityException {
		// More at https://en.wikipedia.org/wiki/HKDF
    	// Inspired by https://github.com/patrickfav/hkdf

		KeyStore keyStore = obtainKeyStore();

		Key key = keyStore.getKey(alias, null);
		if (key == null) return null; // No key pair

		RSAPrivateKey privateKey = (RSAPrivateKey)key;

		int ikmLenght = privateKey.getModulus().bitLength() / 8;
		byte[] nounce = new byte[ikmLenght];

		for (int i=0; i<ikmLenght; i+=1)
		{
			nounce[i] = 0x77;
		}

		Cipher cipher = Cipher.getInstance("RSA/ECB/NoPadding");
		cipher.init(Cipher.DECRYPT_MODE, privateKey);

		byte[] ikm; // input Keying Material
		try {
			ikm = cipher.doFinal(nounce);
		} catch (GeneralSecurityException e) {

			if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
				if (e instanceof UserNotAuthenticatedException)
				{
					Log.w(TAG, "User not logged in!");
					throw new UserAuth.UserNotAuthenticatedException(e);
				}
			}

			throw e;
		}

		Mac HMAC = Mac.getInstance("HmacSHA256");
		SecretKey salt = new SecretKeySpec(new byte[HMAC.getMacLength()], "HmacSHA256");
		HMAC.init(salt);
		SecretKey prk = new SecretKeySpec(HMAC.doFinal(ikm),"HmacSHA256");
		for (int i=0; i<ikmLenght; i+=1)
		{
			nounce[i] = 0x77;
		}

		byte[] t = new byte[0];

		int iterations = (int) Math.ceil(((double) outLengthBytes) / ((double) HMAC.getMacLength()));

		if (iterations > 255) {
			throw new IllegalArgumentException("out length must be maximal 255 * hash-length; requested: " + outLengthBytes + " bytes");
		}

		ByteBuffer buffer = ByteBuffer.allocate(outLengthBytes);
		int remainingBytes = outLengthBytes;
		int stepSize;

		for (int i = 0; i < iterations; i++) {
			HMAC = Mac.getInstance("HmacSHA256");
			HMAC.init(prk);

			HMAC.update(t);
			HMAC.update(keyId.getBytes());
			HMAC.update((byte) (i + 1));

			t = HMAC.doFinal();

			stepSize = Math.min(remainingBytes, t.length);

			buffer.put(t, 0, stepSize);
			remainingBytes -= stepSize;
		}

		return buffer.array();
	}


    public void generate(Context context, int keySize, String subject, Date valid_from, Date valid_to, int serialNumber, boolean requireUserAuth) throws GeneralSecurityException {

        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.JELLY_BEAN_MR2) {
			generate_api17(context, keySize, subject, valid_from, valid_to, serialNumber, requireUserAuth);
        }
        else if (Build.VERSION.SDK_INT < Build.VERSION_CODES.M) {
            generate_api18_22(context, keySize, subject, valid_from, valid_to, serialNumber, requireUserAuth);
        }
        else {
            generate_api23(keySize, subject, valid_from, valid_to, serialNumber, requireUserAuth);
        }


    }

	private void generate_api17(Context context, int keySize, String subject, Date valid_from, Date valid_to, int serialNumber, boolean requireUserAuth) throws GeneralSecurityException {

		X500Principal subjectPrincipal = new X500Principal(subject);
		KeyStore keyStore = obtainKeyStore();

		KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", "BC");
		kpg.initialize(keySize);
		KeyPair keyPair = kpg.genKeyPair();

		//TODO: This code is not completed: how to generate self-signed certificate on Android <=17?
	}

	@TargetApi(Build.VERSION_CODES.JELLY_BEAN_MR2)
    private void generate_api18_22(Context context, int keySize, String subject, Date valid_from, Date valid_to, int serialNumber, boolean requireUserAuth) throws GeneralSecurityException {

        Context applicationContext = context.getApplicationContext();
        X500Principal subjectPrincipal = new X500Principal(subject);

        KeyStore keyStore = obtainKeyStore();

        KeyPairGeneratorSpec.Builder builder = new KeyPairGeneratorSpec.Builder(applicationContext);
        builder.setAlias(alias);
        builder.setStartDate(valid_from);
        builder.setEndDate(valid_to);
        builder.setSerialNumber(BigInteger.valueOf(serialNumber));
        builder.setSubject(subjectPrincipal);

        if (requireUserAuth) {
            builder.setEncryptionRequired();
        }

        // API level 18 has RSA key fixed to 2048
        // See http://stackoverflow.com/questions/39998087/how-to-set-key-size-for-keypairgeneratorspec-on-api-18
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.KITKAT) {
            builder.setKeySize(keySize);
        }

        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", "AndroidKeyStore");
        kpg.initialize(builder.build());

        KeyPair kp = kpg.generateKeyPair();

        PrivateKey privateKey = (PrivateKey) keyStore.getKey(alias, null);
        if (privateKey == null)
            throw new SecurityException("Failed to obtain private key from a generated key pair");

        PublicKey publicKey = keyStore.getCertificate(alias).getPublicKey();
        if (publicKey == null)
            throw new SecurityException("Failed to obtain private key from a generated key pair");
    }

    @TargetApi(Build.VERSION_CODES.M)
    private void generate_api23(int keySize, String subject, Date valid_from, Date valid_to, int serialNumber, boolean requireUserAuth) throws GeneralSecurityException {

        X500Principal subjectPrincipal = new X500Principal(subject);

        KeyStore keyStore = obtainKeyStore();

        KeyGenParameterSpec.Builder builder = new KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT);
        builder.setKeySize(keySize);
        builder.setBlockModes(KeyProperties.BLOCK_MODE_ECB); // For backward compatibility
        builder.setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_RSA_PKCS1); // For backward compatibility

        builder.setCertificateNotBefore(valid_from);
        builder.setCertificateNotAfter(valid_to);
        builder.setCertificateSerialNumber(BigInteger.valueOf(serialNumber));
        builder.setCertificateSubject(subjectPrincipal);

        if (requireUserAuth) {
            builder.setUserAuthenticationRequired(true);
            builder.setUserAuthenticationValidityDurationSeconds(5 * 60);
        }

        KeyPairGenerator kpg = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_RSA, "AndroidKeyStore");

        kpg.initialize(builder.build());

        KeyPair kp = kpg.generateKeyPair();

        PrivateKey privateKey = (PrivateKey) keyStore.getKey(alias, null);
        if (privateKey == null)
            throw new SecurityException("Failed to obtain private key from a generated key pait");

        PublicKey publicKey = keyStore.getCertificate(alias).getPublicKey();
        if (publicKey == null)
            throw new SecurityException("Failed to obtain private key from a generated key pait");

        // Following code works only on API 23+
        //KeyFactory kf = KeyFactory.getInstance(privateKey.getAlgorithm(), "AndroidKeyStore");
        //KeyInfo keyInfo = kf.getKeySpec(privateKey, KeyInfo.class);
        //Log.i(TAG, "Pair: " + privateKey + " / " + publicKey + " isInHardware:" + keyInfo.isInsideSecureHardware());
    }


    private KeyStore obtainKeyStore() throws GeneralSecurityException {
		KeyStore keyStore;
		if (Build.VERSION.SDK_INT < Build.VERSION_CODES.JELLY_BEAN_MR2) {
			keyStore = KeyStore.getInstance("BKS");
		}
		else {
			keyStore = KeyStore.getInstance("AndroidKeyStore");
			try {
				keyStore.load(null);
			} catch (IOException e) {
				throw new KeyStoreException("Key store error", e);
			}
		}
        return keyStore;
    }


    public Certificate getCertificate() throws GeneralSecurityException {
        KeyStore keyStore = obtainKeyStore();
        if (keyStore == null) return null;
        return keyStore.getCertificate(alias);
    }

    public PublicKey getPublicKey() throws GeneralSecurityException {
        Certificate cert = getCertificate();
        if (cert == null) return null;
        return cert.getPublicKey();
    }

}
