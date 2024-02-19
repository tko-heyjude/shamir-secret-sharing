package com.ncp.scenario;

import static org.junit.jupiter.api.Assertions.*;

import java.util.Base64;
import java.util.Map;
import java.util.Random;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;

class CryptoWrapperTest {

	static CryptoWrapper cryptoWrapper = new CryptoWrapper();
	static TestFixture testFixture = new TestFixture();

	@BeforeAll
	static void makePlaintext() {
		// generate test plaintext
		Random random = new Random();
		final byte[] buffer = new byte[20];
		random.nextBytes(buffer);
		testFixture.plaintext = Base64.getEncoder().encodeToString(buffer);
	}

	@Test
	@Order(1)
	void encrypt() throws Exception {
		byte[] plaintextByte = Base64.getDecoder().decode(testFixture.getPlaintext());
		Map<String, String> ret = cryptoWrapper.encrypt(plaintextByte);

		testFixture.shard1 = ret.get("shard1");
		testFixture.shard2 = ret.get("shard2");
		testFixture.ciphertext = ret.get("ciphertext");
		testFixture.iv = ret.get("iv");

		assertAll(
			() -> assertNotNull(testFixture.getShard1()),
			() -> assertNotNull(testFixture.getShard2()),
			() -> assertNotNull(testFixture.getCiphertext()),
			() -> assertNotNull(testFixture.getIv())
		);
	}

	@Test
	@Order(2)
	void decrypt() throws Exception {
		String plaintext = cryptoWrapper.decrypt(
			testFixture.getCiphertext(),
			testFixture.getIv(),
			testFixture.getShard1(),
			testFixture.getShard2());

		assertEquals(plaintext, testFixture.getPlaintext());
	}

}