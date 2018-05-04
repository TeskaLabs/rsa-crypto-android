# rsa-crypto-android

Demonstration of the RSA cryptography on various versions of the Android.
It covers following operations:

 - Key pair generation
 - Encryption
 - Decryption
 - Key derivation
 

## Why RSA?

We closed RSA 2048 because it seems to be supported on the most versions of the Android.

## Overview of the relevant Android API changes

### API 18

Android Keystore provider feature that was introduced in Android 4.3 (API level 18). 

### API 19

Supports other than 2048bit RSA keys in generateKeyPair().

### API  23

Keystore redesign in Android M (fingerprint authorization introduced etc.)

