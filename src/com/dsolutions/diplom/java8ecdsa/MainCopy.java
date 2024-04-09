package com.dsolutions.diplom.java8ecdsa;

import com.starkbank.ellipticcurve.*;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.util.Arrays;

public class MainCopy {

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

    public static void main(String[] args) throws NoSuchAlgorithmException {
        Security.addProvider(new SHA256BytesDigestProvider());
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

        String rawMsg = "{\"DEGREE_NUMBER\":\"D202400649\",\"PRIMARY_IDENTIFIER_NUMBER\":\"ха87060111\",\"INSTITUTION_ID\":35623,\"INSTITUTION_NAME\":\"ШУТИС /Шинжлэх ухаан технологийн их сургууль/\",\"EDUCATION_LEVEL_NAME\":\"Бакалаврын боловсрол\",\"EDUCATION_FIELD_CODE\":\"061304\",\"EDUCATION_FIELD_NAME\":\"Мэдээллийн технологи\",\"TOTAL_GPA\":3.6,\"LAST_NAME\":\"Цолмон\",\"FIRST_NAME\":\"Баяр\",\"CONFER_YEAR_NAME\":\"2023-2024 хичээлийн жил\"}";
        String hash = "31ea30a51a59297a6471ee45afbc35627cf01263b4478f7f10ddffe88085a173";

        final MessageDigest md = MessageDigest.getInstance("CustomAlgorithm");
        final byte[] r = md.digest(hash.getBytes());
        System.out.println("digest:");
        System.out.println(new String(r, StandardCharsets.UTF_8));

        // Generate Signature
        System.out.println(new String(MessageDigest.getInstance("SHA-256").digest(rawMsg.getBytes())));
        Signature signature = Ecdsa.sign(rawMsg, privateKey);

        // Verify if signature is valid
        boolean verified = Ecdsa.verify(rawMsg, signature, publicKey) ;

        // Return the signature verification status
        System.out.println("Message: " + hash);
        System.out.println("Signature: " + signature.toBase64());
        System.out.println("Verified: " + verified);
    }
}
