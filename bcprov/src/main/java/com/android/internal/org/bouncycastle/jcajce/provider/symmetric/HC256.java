package com.android.internal.org.bouncycastle.jcajce.provider.symmetric;

import com.android.internal.org.bouncycastle.crypto.CipherKeyGenerator;
import com.android.internal.org.bouncycastle.crypto.engines.HC256Engine;
import com.android.internal.org.bouncycastle.jcajce.provider.config.ConfigurableProvider;
import com.android.internal.org.bouncycastle.jcajce.provider.symmetric.util.BaseKeyGenerator;
import com.android.internal.org.bouncycastle.jcajce.provider.symmetric.util.BaseStreamCipher;
import com.android.internal.org.bouncycastle.jcajce.provider.symmetric.util.IvAlgorithmParameters;
import com.android.internal.org.bouncycastle.jcajce.provider.util.AlgorithmProvider;

public final class HC256
{
    private HC256()
    {
    }
    
    public static class Base
        extends BaseStreamCipher
    {
        public Base()
        {
            super(new HC256Engine(), 32);
        }
    }

    public static class KeyGen
        extends BaseKeyGenerator
    {
        public KeyGen()
        {
            super("HC256", 256, new CipherKeyGenerator());
        }
    }

    public static class AlgParams
        extends IvAlgorithmParameters
    {
        protected String engineToString()
        {
            return "HC256 IV";
        }
    }

    public static class Mappings
        extends AlgorithmProvider
    {
        private static final String PREFIX = HC256.class.getName();

        public Mappings()
        {
        }

        public void configure(ConfigurableProvider provider)
        {
            provider.addAlgorithm("Cipher.HC256", PREFIX + "$Base");
            provider.addAlgorithm("KeyGenerator.HC256", PREFIX + "$KeyGen");
            provider.addAlgorithm("AlgorithmParameters.HC256", PREFIX + "$AlgParams");
        }
    }
}
