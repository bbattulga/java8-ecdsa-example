package com.dsolutions.diplom.java8ecdsa;

import com.starkbank.ellipticcurve.*;

import java.math.BigInteger;
import java.util.Arrays;

public class Main {

    static Curve p384Curve = new Curve(
                new BigInteger("0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000fffffffc".replace("0x", ""), 16),
                new BigInteger("0xb3312fa7e23ee7e4988e056be3f82d19181d9c6efe8141120314088f5013875ac656398d8a2ed19d2a85c8edd3ec2aef".replace("0x", ""), 16),
                new BigInteger("0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffff".replace("0x", ""), 16),
                new BigInteger("0xffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973".replace("0x", ""), 16),
                new BigInteger("0xaa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab7".replace("0x", ""), 16),
                new BigInteger("0x3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5f".replace("0x", ""), 16),
                "P-384",
                new long[]{1L, 3L, 132L, 0L, 34L}
    );

    public static void main(String[] args)  {
        Curve.supportedCurves.add(p384Curve);
        Curve.curvesByOid.put(Arrays.hashCode(p384Curve.oid), p384Curve);
        final String privateKeyPem = "-----BEGIN EC PRIVATE KEY-----\n" +
                "MIGkAgEBBDA/2ZxcwUyM0VrY74puQsYrfO8PvHoNBXwFQvQrkZV+4l+qEqvWI5hi\n" +
                "PSOwjejO61+gBwYFK4EEACKhZANiAARxdmPLboNHuZKxWWsaRo3gSUzlNM155owF\n" +
                "IURnx7JK7+/KLX/hDUs4BYdKuGbGl0zV0pgJjpOBSjWDD+ZIxG9vx85ggjiYgECd\n" +
                "g/TNYS7M9kb4Rh192CGcUIDuXSY1ui0=\n" +
                "-----END EC PRIVATE KEY-----\n";
        final String publicKeyPem = "-----BEGIN PUBLIC KEY-----\n" +
                "MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEcXZjy26DR7mSsVlrGkaN4ElM5TTNeeaM\n" +
                "BSFEZ8eySu/vyi1/4Q1LOAWHSrhmxpdM1dKYCY6TgUo1gw/mSMRvb8fOYII4mIBA\n" +
                "nYP0zWEuzPZG+EYdfdghnFCA7l0mNbot\n" +
                "-----END PUBLIC KEY-----\n";
        final PrivateKey privateKey = PrivateKey.fromPem(privateKeyPem);
        final PublicKey publicKey = PublicKey.fromPem(publicKeyPem);
        String message = "Testing message";
        // Generate Signature
        Signature signature = Ecdsa.sign(message, privateKey);

        // Verify if signature is valid
        boolean verified = Ecdsa.verify(message, signature, publicKey) ;

        // Return the signature verification status
        System.out.println("Message: " + message);
        System.out.println("Signature: " + signature.toBase64());
        System.out.println("Verified: " + verified);
    }
}
