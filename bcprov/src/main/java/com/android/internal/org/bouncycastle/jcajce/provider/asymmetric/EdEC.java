package com.android.internal.org.bouncycastle.jcajce.provider.asymmetric;

import java.util.HashMap;
import java.util.Map;

import com.android.internal.org.bouncycastle.internal.asn1.edec.EdECObjectIdentifiers;
import com.android.internal.org.bouncycastle.jcajce.provider.asymmetric.edec.KeyFactorySpi;
import com.android.internal.org.bouncycastle.jcajce.provider.config.ConfigurableProvider;
import com.android.internal.org.bouncycastle.jcajce.provider.util.AsymmetricAlgorithmProvider;

public class EdEC
{
    private static final String PREFIX = "org.bouncycastle.jcajce.provider.asymmetric" + ".edec.";

    private static final Map<String, String> edxAttributes = new HashMap<String, String>();

    static
    {
        edxAttributes.put("SupportedKeyClasses", "java.security.interfaces.ECPublicKey|java.security.interfaces.ECPrivateKey");
        edxAttributes.put("SupportedKeyFormats", "PKCS#8|X.509");
    }

    public static class Mappings
        extends AsymmetricAlgorithmProvider
    {
        public Mappings()
        {
        }

        public void configure(ConfigurableProvider provider)
        {
            provider.addAlgorithm("KeyFactory.XDH", PREFIX + "KeyFactorySpi$XDH");
            provider.addAlgorithm("KeyFactory.X448", PREFIX + "KeyFactorySpi$X448");
            provider.addAlgorithm("KeyFactory.X25519", PREFIX + "KeyFactorySpi$X25519");

            provider.addAlgorithm("KeyFactory.EDDSA", PREFIX + "KeyFactorySpi$EdDSA");
            provider.addAlgorithm("KeyFactory.ED448", PREFIX + "KeyFactorySpi$Ed448");
            provider.addAlgorithm("KeyFactory.ED25519", PREFIX + "KeyFactorySpi$Ed25519");

            provider.addAlgorithm("Signature.EDDSA", PREFIX + "SignatureSpi$EdDSA");
            provider.addAlgorithm("Signature.ED448", PREFIX + "SignatureSpi$Ed448");
            provider.addAlgorithm("Signature.ED25519", PREFIX + "SignatureSpi$Ed25519");
            provider.addAlgorithm("Alg.Alias.Signature", EdECObjectIdentifiers.id_Ed448, "ED448");
            provider.addAlgorithm("Alg.Alias.Signature", EdECObjectIdentifiers.id_Ed25519, "ED25519");

            provider.addAlgorithm("KeyPairGenerator.EDDSA", PREFIX + "KeyPairGeneratorSpi$EdDSA");
            provider.addAlgorithm("KeyPairGenerator.ED448", PREFIX + "KeyPairGeneratorSpi$Ed448");
            provider.addAlgorithm("KeyPairGenerator.ED25519", PREFIX + "KeyPairGeneratorSpi$Ed25519");
            provider.addAlgorithm("KeyPairGenerator", EdECObjectIdentifiers.id_Ed448, PREFIX + "KeyPairGeneratorSpi$Ed448");
            provider.addAlgorithm("KeyPairGenerator", EdECObjectIdentifiers.id_Ed25519, PREFIX + "KeyPairGeneratorSpi$Ed25519");

            provider.addAlgorithm("KeyAgreement.XDH", PREFIX + "KeyAgreementSpi$XDH");
            provider.addAlgorithm("KeyAgreement.X448", PREFIX + "KeyAgreementSpi$X448");
            provider.addAlgorithm("KeyAgreement.X25519", PREFIX + "KeyAgreementSpi$X25519");
            provider.addAlgorithm("KeyAgreement", EdECObjectIdentifiers.id_X448, PREFIX + "KeyAgreementSpi$X448");
            provider.addAlgorithm("KeyAgreement", EdECObjectIdentifiers.id_X25519, PREFIX + "KeyAgreementSpi$X25519");

            provider.addAlgorithm("KeyAgreement.X25519WITHSHA256CKDF", PREFIX + "KeyAgreementSpi$X25519withSHA256CKDF");
            provider.addAlgorithm("KeyAgreement.X25519WITHSHA384CKDF", PREFIX + "KeyAgreementSpi$X25519withSHA384CKDF");
            provider.addAlgorithm("KeyAgreement.X25519WITHSHA512CKDF", PREFIX + "KeyAgreementSpi$X25519withSHA512CKDF");

            provider.addAlgorithm("KeyAgreement.X448WITHSHA256CKDF", PREFIX + "KeyAgreementSpi$X448withSHA256CKDF");
            provider.addAlgorithm("KeyAgreement.X448WITHSHA384CKDF", PREFIX + "KeyAgreementSpi$X448withSHA384CKDF");
            provider.addAlgorithm("KeyAgreement.X448WITHSHA512CKDF", PREFIX + "KeyAgreementSpi$X448withSHA512CKDF");

            provider.addAlgorithm("KeyAgreement.X25519WITHSHA256KDF", PREFIX + "KeyAgreementSpi$X25519withSHA256KDF");
            provider.addAlgorithm("KeyAgreement.X448WITHSHA512KDF", PREFIX + "KeyAgreementSpi$X448withSHA512KDF");

            provider.addAlgorithm("KeyAgreement.X25519UWITHSHA256KDF", PREFIX + "KeyAgreementSpi$X25519UwithSHA256KDF");
            provider.addAlgorithm("KeyAgreement.X448UWITHSHA512KDF", PREFIX + "KeyAgreementSpi$X448UwithSHA512KDF");

            provider.addAlgorithm("KeyAgreement.X448withSHA512HKDF", PREFIX + "KeyAgreementSpi$X448withSHA512HKDF");
            provider.addAlgorithm("KeyAgreement.X25519withSHA256HKDF", PREFIX + "KeyAgreementSpi$X25519withSHA256HKDF");

            provider.addAlgorithm("KeyPairGenerator.XDH", PREFIX + "KeyPairGeneratorSpi$XDH");
            provider.addAlgorithm("KeyPairGenerator.X448", PREFIX + "KeyPairGeneratorSpi$X448");
            provider.addAlgorithm("KeyPairGenerator.X25519", PREFIX + "KeyPairGeneratorSpi$X25519");
            provider.addAlgorithm("KeyPairGenerator", EdECObjectIdentifiers.id_X448, PREFIX + "KeyPairGeneratorSpi$X448");
            provider.addAlgorithm("KeyPairGenerator", EdECObjectIdentifiers.id_X25519, PREFIX + "KeyPairGeneratorSpi$X25519");

            provider.addAlgorithm("Cipher.XIES", PREFIX + "IESCipher$XIES");
            provider.addAlgorithm("Cipher.XIESwithSHA1", PREFIX + "IESCipher$XIES");
            provider.addAlgorithm("Cipher.XIESWITHSHA1", PREFIX + "IESCipher$XIES");
            provider.addAlgorithm("Cipher.XIESwithSHA256", PREFIX + "IESCipher$XIESwithSHA256");
            provider.addAlgorithm("Cipher.XIESWITHSHA256", PREFIX + "IESCipher$XIESwithSHA256");
            provider.addAlgorithm("Cipher.XIESwithSHA384", PREFIX + "IESCipher$XIESwithSHA384");
            provider.addAlgorithm("Cipher.XIESWITHSHA384", PREFIX + "IESCipher$XIESwithSHA384");
            provider.addAlgorithm("Cipher.XIESwithSHA512", PREFIX + "IESCipher$XIESwithSHA512");
            provider.addAlgorithm("Cipher.XIESWITHSHA512", PREFIX + "IESCipher$XIESwithSHA512");

            provider.addAlgorithm("Cipher.XIESwithAES-CBC", PREFIX + "IESCipher$XIESwithAESCBC");
            provider.addAlgorithm("Cipher.XIESWITHAES-CBC", PREFIX + "IESCipher$XIESwithAESCBC");
            provider.addAlgorithm("Cipher.XIESwithSHA1andAES-CBC", PREFIX + "IESCipher$XIESwithAESCBC");
            provider.addAlgorithm("Cipher.XIESWITHSHA1ANDAES-CBC", PREFIX + "IESCipher$XIESwithAESCBC");
            provider.addAlgorithm("Cipher.XIESwithSHA256andAES-CBC", PREFIX + "IESCipher$XIESwithSHA256andAESCBC");
            provider.addAlgorithm("Cipher.XIESWITHSHA256ANDAES-CBC", PREFIX + "IESCipher$XIESwithSHA256andAESCBC");
            provider.addAlgorithm("Cipher.XIESwithSHA384andAES-CBC", PREFIX + "IESCipher$XIESwithSHA384andAESCBC");
            provider.addAlgorithm("Cipher.XIESWITHSHA384ANDAES-CBC", PREFIX + "IESCipher$XIESwithSHA384andAESCBC");
            provider.addAlgorithm("Cipher.XIESwithSHA512andAES-CBC", PREFIX + "IESCipher$XIESwithSHA512andAESCBC");
            provider.addAlgorithm("Cipher.XIESWITHSHA512ANDAES-CBC", PREFIX + "IESCipher$XIESwithSHA512andAESCBC");

            registerOid(provider, EdECObjectIdentifiers.id_X448, "XDH", new KeyFactorySpi.X448());
            registerOid(provider, EdECObjectIdentifiers.id_X25519, "XDH", new KeyFactorySpi.X25519());
            registerOid(provider, EdECObjectIdentifiers.id_Ed448, "EDDSA", new KeyFactorySpi.Ed448());
            registerOid(provider, EdECObjectIdentifiers.id_Ed25519, "EDDSA", new KeyFactorySpi.Ed25519());
        }
    }
}
