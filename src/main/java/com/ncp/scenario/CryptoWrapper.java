package com.ncp.scenario;

import java.security.SecureRandom;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import com.codahale.shamir.Scheme;

public class CryptoWrapper {

	private static final String CIPHER_TYPE = "AES";
	private static final String CIPHER_MODE_PADDING = "/CBC/PKCS5Padding";
	private static final int KEY_LENGTH = 256;

	public Map<String, String> encrypt(byte[] plaintext) throws Exception {
		KeyGenerator keyGenerator = KeyGenerator.getInstance(CIPHER_TYPE);
		keyGenerator.init(KEY_LENGTH);
		SecretKey secretKey = keyGenerator.generateKey();

		Cipher cipher = Cipher.getInstance(CIPHER_TYPE + CIPHER_MODE_PADDING);
		cipher.init(Cipher.ENCRYPT_MODE, secretKey);
		byte[] iv = cipher.getParameters().getParameterSpec(IvParameterSpec.class).getIV();
		byte[] ciphertext = cipher.doFinal(plaintext);

		Map<Integer, byte[]> shards = getShards(secretKey);

		Map<String, String> ret = new HashMap<>();
		ret.put("shard1", encodeToBase64(shards.get(1)));
		ret.put("shard2", encodeToBase64(shards.get(2)));
		ret.put("ciphertext", encodeToBase64(ciphertext));
		ret.put("iv", encodeToBase64(iv));

		return ret;
	}

	public String decrypt(String ciphertext, String iv, String shard1, String shard2) throws Exception {
		SecretKey secretKey = getSecretKey(shard1, shard2);
		IvParameterSpec ivParameterSpec = new IvParameterSpec(decodeFromBase64(iv));
		Cipher cipher = Cipher.getInstance(CIPHER_TYPE + CIPHER_MODE_PADDING);
		cipher.init(Cipher.DECRYPT_MODE, secretKey, ivParameterSpec);

		return encodeToBase64(cipher.doFinal(decodeFromBase64(ciphertext)));
	}

	private SecretKey getSecretKey(String shard1, String shard2) {
		if (shard1 == null || shard1.isEmpty()) {
			throw new IllegalArgumentException();
		}

		if (shard2 == null || shard2.isEmpty()) {
			throw new IllegalArgumentException();
		}

		Map<Integer, byte[]> shards = new HashMap<>();
		shards.put(1, decodeFromBase64(shard1));
		shards.put(2, decodeFromBase64(shard2));
		Scheme scheme = new Scheme(new SecureRandom(), 2, 2); // new SecureRandom() 이 다르면 안되나?
		byte[] mergedKey = scheme.join(shards);

		return new SecretKeySpec(mergedKey, 0, mergedKey.length, CIPHER_TYPE);
	}

	private Map<Integer, byte[]> getShards(SecretKey secretKey) {
		Scheme scheme = new Scheme(new SecureRandom(), 2, 2);
		return scheme.split(secretKey.getEncoded());
	}

	private String encodeToBase64(byte[] bytesToEncode) {
		return Base64.getEncoder().encodeToString(bytesToEncode);
	}

	private byte[] decodeFromBase64(String stringToDecode) {
		return Base64.getDecoder().decode(stringToDecode);
	}
}
