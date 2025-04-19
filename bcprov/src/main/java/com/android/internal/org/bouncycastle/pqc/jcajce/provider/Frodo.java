package com.android.internal.org.bouncycastle.pqc.jcajce.provider;

import com.android.internal.org.bouncycastle.asn1.bc.BCObjectIdentifiers;
import com.android.internal.org.bouncycastle.jcajce.provider.config.ConfigurableProvider;
import com.android.internal.org.bouncycastle.jcajce.provider.util.AsymmetricAlgorithmProvider;
import com.android.internal.org.bouncycastle.jcajce.provider.util.AsymmetricKeyInfoConverter;
import com.android.internal.org.bouncycastle.pqc.jcajce.provider.frodo.FrodoKeyFactorySpi;

public class Frodo
{
    private static final String PREFIX = "org.bouncycastle.pqc.jcajce.provider" + ".frodo.";

    public static class Mappings
        extends AsymmetricAlgorithmProvider
    {
        public Mappings()
        {
        }

        public void configure(ConfigurableProvider provider)
        {
            provider.addAlgorithm("KeyFactory.FRODO", PREFIX + "FrodoKeyFactorySpi");
            provider.addAlgorithm("KeyPairGenerator.FRODO", PREFIX + "FrodoKeyPairGeneratorSpi");

            provider.addAlgorithm("KeyGenerator.FRODO", PREFIX + "FrodoKeyGeneratorSpi");

            AsymmetricKeyInfoConverter keyFact = new FrodoKeyFactorySpi();

            provider.addAlgorithm("Cipher.FRODO", PREFIX + "FrodoCipherSpi$Base");
            provider.addAlgorithm("Alg.Alias.Cipher." + BCObjectIdentifiers.pqc_kem_frodo, "FRODO");

            registerOid(provider, BCObjectIdentifiers.pqc_kem_frodo, "Frodo", keyFact);
        }
    }
}
