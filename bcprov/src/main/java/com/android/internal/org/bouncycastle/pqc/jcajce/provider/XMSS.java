package com.android.internal.org.bouncycastle.pqc.jcajce.provider;

import com.android.internal.org.bouncycastle.asn1.bc.BCObjectIdentifiers;
import com.android.internal.org.bouncycastle.internal.asn1.isara.IsaraObjectIdentifiers;
import com.android.internal.org.bouncycastle.jcajce.provider.config.ConfigurableProvider;
import com.android.internal.org.bouncycastle.jcajce.provider.util.AsymmetricAlgorithmProvider;
import com.android.internal.org.bouncycastle.pqc.asn1.PQCObjectIdentifiers;
import com.android.internal.org.bouncycastle.pqc.jcajce.provider.xmss.XMSSKeyFactorySpi;
import com.android.internal.org.bouncycastle.pqc.jcajce.provider.xmss.XMSSMTKeyFactorySpi;

public class XMSS
{
    private static final String PREFIX = "org.bouncycastle.pqc.jcajce.provider" + ".xmss.";

    public static class Mappings
        extends AsymmetricAlgorithmProvider
    {
        public Mappings()
        {
        }

        public void configure(ConfigurableProvider provider)
        {
            provider.addAlgorithm("KeyFactory.XMSS", PREFIX + "XMSSKeyFactorySpi");
            provider.addAlgorithm("KeyPairGenerator.XMSS", PREFIX + "XMSSKeyPairGeneratorSpi");

            provider.addAlgorithm("Signature.XMSS", PREFIX + "XMSSSignatureSpi$generic");
            provider.addAlgorithm("Alg.Alias.Signature." + IsaraObjectIdentifiers.id_alg_xmss, "XMSS");
            provider.addAlgorithm("Alg.Alias.Signature.OID." + IsaraObjectIdentifiers.id_alg_xmss, "XMSS");

            addSignatureAlgorithm(provider, "XMSS-SHA256", PREFIX + "XMSSSignatureSpi$withSha256", BCObjectIdentifiers.xmss_SHA256);
            addSignatureAlgorithm(provider, "XMSS-SHAKE128", PREFIX + "XMSSSignatureSpi$withShake128", BCObjectIdentifiers.xmss_SHAKE128);
            addSignatureAlgorithm(provider, "XMSS-SHA512", PREFIX + "XMSSSignatureSpi$withSha512", BCObjectIdentifiers.xmss_SHA512);
            addSignatureAlgorithm(provider, "XMSS-SHAKE256", PREFIX + "XMSSSignatureSpi$withShake256", BCObjectIdentifiers.xmss_SHAKE256);

            addSignatureAlgorithm(provider, "SHA256", "XMSS-SHA256", PREFIX + "XMSSSignatureSpi$withSha256andPrehash", BCObjectIdentifiers.xmss_SHA256ph);
            addSignatureAlgorithm(provider, "SHAKE128", "XMSS-SHAKE128", PREFIX + "XMSSSignatureSpi$withShake128andPrehash", BCObjectIdentifiers.xmss_SHAKE128ph);
            addSignatureAlgorithm(provider, "SHAKE128(512)", "XMSS-SHAKE128", PREFIX + "XMSSSignatureSpi$withShake128_512andPrehash", BCObjectIdentifiers.xmss_SHAKE128_512ph);
            addSignatureAlgorithm(provider, "SHA512", "XMSS-SHA512", PREFIX + "XMSSSignatureSpi$withSha512andPrehash", BCObjectIdentifiers.xmss_SHA512ph);
            addSignatureAlgorithm(provider, "SHAKE256", "XMSS-SHAKE256", PREFIX + "XMSSSignatureSpi$withShake256andPrehash", BCObjectIdentifiers.xmss_SHAKE256ph);
            addSignatureAlgorithm(provider, "SHAKE256(1024)", "XMSS-SHAKE256", PREFIX + "XMSSSignatureSpi$withShake256_1024andPrehash", BCObjectIdentifiers.xmss_SHAKE256_1024ph);
            provider.addAlgorithm("Alg.Alias.Signature.SHA256WITHXMSS", "SHA256WITHXMSS-SHA256");
            provider.addAlgorithm("Alg.Alias.Signature.SHAKE128WITHXMSS", "SHAKE128WITHXMSS-SHAKE128");
            provider.addAlgorithm("Alg.Alias.Signature.SHAKE128(512)WITHXMSS", "SHAKE128(512)WITHXMSS-SHAKE128");
            provider.addAlgorithm("Alg.Alias.Signature.SHA512WITHXMSS", "SHA512WITHXMSS-SHA512");
            provider.addAlgorithm("Alg.Alias.Signature.SHAKE256WITHXMSS", "SHAKE256WITHXMSS-SHAKE256");
            provider.addAlgorithm("Alg.Alias.Signature.SHAKE256(1024)WITHXMSS", "SHAKE256(1024)WITHXMSS-SHAKE256");

            provider.addAlgorithm("KeyFactory.XMSSMT", PREFIX + "XMSSMTKeyFactorySpi");
            provider.addAlgorithm("KeyPairGenerator.XMSSMT", PREFIX + "XMSSMTKeyPairGeneratorSpi");

            provider.addAlgorithm("Signature.XMSSMT", PREFIX + "XMSSMTSignatureSpi$generic");
            provider.addAlgorithm("Alg.Alias.Signature." + IsaraObjectIdentifiers.id_alg_xmssmt, "XMSSMT");
            provider.addAlgorithm("Alg.Alias.Signature.OID." + IsaraObjectIdentifiers.id_alg_xmssmt, "XMSSMT");

            addSignatureAlgorithm(provider, "XMSSMT-SHA256", PREFIX + "XMSSMTSignatureSpi$withSha256", BCObjectIdentifiers.xmss_mt_SHA256);
            addSignatureAlgorithm(provider, "XMSSMT-SHAKE128", PREFIX + "XMSSMTSignatureSpi$withShake128", BCObjectIdentifiers.xmss_mt_SHAKE128);
            addSignatureAlgorithm(provider, "XMSSMT-SHA512", PREFIX + "XMSSMTSignatureSpi$withSha512", BCObjectIdentifiers.xmss_mt_SHA512);
            addSignatureAlgorithm(provider, "XMSSMT-SHAKE256", PREFIX + "XMSSMTSignatureSpi$withShake256", BCObjectIdentifiers.xmss_mt_SHAKE256);

            addSignatureAlgorithm(provider, "SHA256", "XMSSMT-SHA256", PREFIX + "XMSSMTSignatureSpi$withSha256andPrehash", BCObjectIdentifiers.xmss_mt_SHA256ph);
            addSignatureAlgorithm(provider, "SHAKE128", "XMSSMT-SHAKE128", PREFIX + "XMSSMTSignatureSpi$withShake128andPrehash", BCObjectIdentifiers.xmss_mt_SHAKE128ph);
            addSignatureAlgorithm(provider, "SHAKE128(512)", "XMSSMT-SHAKE128", PREFIX + "XMSSMTSignatureSpi$withShake128_512andPrehash", BCObjectIdentifiers.xmss_mt_SHAKE128_512ph);
            addSignatureAlgorithm(provider, "SHA512", "XMSSMT-SHA512", PREFIX + "XMSSMTSignatureSpi$withSha512andPrehash", BCObjectIdentifiers.xmss_mt_SHA512ph);
            addSignatureAlgorithm(provider, "SHAKE256", "XMSSMT-SHAKE256", PREFIX + "XMSSMTSignatureSpi$withShake256andPrehash", BCObjectIdentifiers.xmss_mt_SHAKE256ph);
            addSignatureAlgorithm(provider, "SHAKE256(1024)", "XMSSMT-SHAKE256", PREFIX + "XMSSMTSignatureSpi$withShake256_1024andPrehash", BCObjectIdentifiers.xmss_mt_SHAKE256_1024ph);
            provider.addAlgorithm("Alg.Alias.Signature.SHA256WITHXMSSMT", "SHA256WITHXMSSMT-SHA256");
            provider.addAlgorithm("Alg.Alias.Signature.SHAKE128WITHXMSSMT", "SHAKE128WITHXMSSMT-SHAKE128");
            provider.addAlgorithm("Alg.Alias.Signature.SHAKE128(512)WITHXMSSMT", "SHAKE128(512)WITHXMSSMT-SHAKE128");
            provider.addAlgorithm("Alg.Alias.Signature.SHA512WITHXMSSMT", "SHA512WITHXMSSMT-SHA512");
            provider.addAlgorithm("Alg.Alias.Signature.SHAKE256WITHXMSSMT", "SHAKE256WITHXMSSMT-SHAKE256");
            provider.addAlgorithm("Alg.Alias.Signature.SHAKE256(1024)WITHXMSSMT", "SHAKE256(1024)WITHXMSSMT-SHAKE256");

            registerOid(provider, PQCObjectIdentifiers.xmss, "XMSS", new XMSSKeyFactorySpi());
            registerOid(provider, IsaraObjectIdentifiers.id_alg_xmss, "XMSS", new XMSSKeyFactorySpi());
            registerOid(provider, PQCObjectIdentifiers.xmss_mt, "XMSSMT", new XMSSMTKeyFactorySpi());
            registerOid(provider, IsaraObjectIdentifiers.id_alg_xmssmt, "XMSSMT", new XMSSMTKeyFactorySpi());
        }
    }
}
