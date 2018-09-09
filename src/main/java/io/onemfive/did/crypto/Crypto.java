package io.onemfive.did.crypto;

import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;

/**
 * Interface for all encryption/signature algorithm combinations supported by
 * Inkrypt CDN. Also contains methods for converting between Base64 keys and
 * key objects.
 *
 * This interface does not define symmetric encryption, which is always AES-256,
 * nor a hash algorithm, which is SHA-256 or SHA-512.
 *
 * Originally from I2P-Bote.
 */
public interface Crypto {
    
    /** Returns a user-friendly name for this <code>Crypto</code>. */
    String getName();
    
    /** Returns a number that identifies this <code>Crypto</code>. */
    byte getId();
    
    /**
     * Returns the number of characters in a Base64 encoding of a pair of public keys (an encryption key and a signing key) -
     * in other words, the length of a CDNPeer hash that uses this <code>Crypto</code>.
     */
    int getBase64PublicKeyPairLength();

    /**
     * Returns the total number of characters in a Base64 encoding of an encryption key pair and a signing key pair -
     * in other words, the length of a CDNPeer that uses this <code>Crypto</code>.
     */
    int getBase64CompleteKeySetLength();
    
    int getByteArrayPublicKeyPairLength();
    
    // 
    // Key generation
    // 
    
    KeyPair generateEncryptionKeyPair() throws GeneralSecurityException;
    
    KeyPair generateSigningKeyPair() throws GeneralSecurityException;

    /** Returns all possible characters that a Base64-encoded Email Destination can init with. */
    String getBase64InitialCharacters();

    // 
    // Key conversion
    // 
    
    /**
     * The toByteArray methods are incompatible with the toBase64 methods.
     * Using this method and base64-encoding the byte array may result in longer strings than calling toBase64 directly.
     */
    byte[] toByteArray(io.onemfive.did.crypto.PublicKeyPair keyPair);
    
    /**
     * The toByteArray methods are incompatible with the toBase64 methods.
     * Using this method and base64-encoding the byte array may result in longer strings than calling toBase64 directly.
     */
    byte[] toByteArray(io.onemfive.did.crypto.PrivateKeyPair keyPair);
    
    /**
     * This is the counterpart to {@link #toByteArray(io.onemfive.did.crypto.PublicKeyPair)}.
     */
    io.onemfive.did.crypto.PublicKeyPair createPublicKeyPair(byte[] bytes) throws GeneralSecurityException;
    
    /**
     * This is the counterpart to {@link #toByteArray(io.onemfive.did.crypto.PrivateKeyPair)}.
     */
    io.onemfive.did.crypto.PrivateKeyPair createPrivateKeyPair(byte[] bytes) throws GeneralSecurityException;
    
    /**
     * The toBase64 methods are incompatible with the toByteArray methods.
     * Using this method may result in shorter strings than calling toByteArray and Base64-encoding the byte array.
     */
    String toBase64(io.onemfive.did.crypto.PublicKeyPair keyPair) throws GeneralSecurityException;
    
    /**
     * Converts a public encryption key to Base64.
     */
    String encryptionKeyToBase64(PublicKey key) throws GeneralSecurityException;
    
    /**
     * The toBase64 methods are incompatible with the toByteArray methods.
     * Using this method may result in shorter strings than calling toByteArray and Base64-encoding the byte array
     */
    String toBase64(io.onemfive.did.crypto.PrivateKeyPair keyPair) throws GeneralSecurityException;
    
    /**
     * This is the counterpart to {@link #toBase64(io.onemfive.did.crypto.PublicKeyPair)}.
     * The toBase64 methods are incompatible with the toByteArray methods.
     * This method may not work with strings obtained by Base64-encoding the result of {@link #toByteArray(io.onemfive.did.crypto.PublicKeyPair)}.
     */
    io.onemfive.did.crypto.PublicKeyPair createPublicKeyPair(String base64) throws GeneralSecurityException;
    
    /**
     * This is the counterpart to {@link #toBase64(io.onemfive.did.crypto.PrivateKeyPair)}.
     * The toBase64 methods are incompatible with the toByteArray methods.
     * This method may not work with strings obtained by Base64-encoding the result of {@link #toByteArray(io.onemfive.did.crypto.PrivateKeyPair)}.
     */
    io.onemfive.did.crypto.PrivateKeyPair createPrivateKeyPair(String base64) throws GeneralSecurityException;
    
    // 
    // Encryption and signing
    // 
    
    byte[] encrypt(byte[] data, PublicKey key) throws GeneralSecurityException;
    
    /** This method takes a public key in addition to the private key because some algorithms need the public key for decryption. */
    byte[] decrypt(byte[] data, PublicKey publicKey, PrivateKey privateKey) throws GeneralSecurityException;
    
    /**
     * @param data
     * @param privateKey
     * @param keyUpdateHandler Called if the signature algorithm alters the private key
     * @return a signature
     * @throws GeneralSecurityException
     */
    byte[] sign(byte[] data, PrivateKey privateKey, io.onemfive.did.crypto.KeyUpdateHandler keyUpdateHandler) throws GeneralSecurityException, io.onemfive.did.crypto.PasswordException;
    
    boolean verify(byte[] data, byte[] signature, PublicKey key) throws GeneralSecurityException;
}