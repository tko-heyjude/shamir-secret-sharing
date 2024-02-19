package com.ncp.scenario;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
public class TestFixture {
	String shard1;
	String shard2;
	String plaintext;
	String ciphertext;
	String iv;
}
