package com.dsolutions.diplom.java8ecdsa;

import java.security.MessageDigestSpi;
import java.security.Provider;

public class SHA256BytesDigestProvider extends Provider {

    public SHA256BytesDigestProvider() {
        super("SHA256 Reverse Digest Provider", 1.0, "Given a sha256 string, returns sha256 bytes");
        put("MessageDigest.SHA-256-BYTES", CustomMessageDigestSpi.class.getName());
    }

    public static class CustomMessageDigestSpi extends MessageDigestSpi {

        private byte[] digest;

        @Override
        protected void engineUpdate(byte input) {
            // Implement your update logic here
        }

        @Override
        protected void engineUpdate(byte[] input, int offset, int len) {
            String s = new String(input);
            // Implement your update logic here
            byte[] data = new byte[s.length() / 2];
            for (int i = 0; i < s.length(); i += 2) {
                data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                        + Character.digit(s.charAt(i+1), 16));
            }
            this.digest = data;
        }

        @Override
        protected byte[] engineDigest() {
            // Return the input data as the digest
            return digest;
        }

        @Override
        protected void engineReset() {
            // Reset the digest
            digest = null;
        }

        @Override
        protected int engineGetDigestLength() {
            // Return the length of the digest
            return this.digest.length;
        }
    }
}
