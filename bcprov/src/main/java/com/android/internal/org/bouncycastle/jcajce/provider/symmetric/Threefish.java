package com.android.internal.org.bouncycastle.jcajce.provider.symmetric;

import com.android.internal.org.bouncycastle.crypto.CipherKeyGenerator;
import com.android.internal.org.bouncycastle.crypto.engines.ThreefishEngine;
import com.android.internal.org.bouncycastle.crypto.macs.CMac;
import com.android.internal.org.bouncycastle.jcajce.provider.config.ConfigurableProvider;
import com.android.internal.org.bouncycastle.jcajce.provider.symmetric.util.BaseBlockCipher;
import com.android.internal.org.bouncycastle.jcajce.provider.symmetric.util.BaseKeyGenerator;
import com.android.internal.org.bouncycastle.jcajce.provider.symmetric.util.BaseMac;
import com.android.internal.org.bouncycastle.jcajce.provider.symmetric.util.IvAlgorithmParameters;
import com.android.internal.org.bouncycastle.jcajce.provider.util.AlgorithmProvider;

public final class Threefish
{
    private Threefish()
    {
    }

    public static class ECB_256
        extends BaseBlockCipher
    {
        public ECB_256()
        {
            super(new ThreefishEngine(ThreefishEngine.BLOCKSIZE_256));
        }
    }

    public static class ECB_512
        extends BaseBlockCipher
    {
        public ECB_512()
        {
            super(new ThreefishEngine(ThreefishEngine.BLOCKSIZE_512));
        }
    }

    public static class ECB_1024
        extends BaseBlockCipher
    {
        public ECB_1024()
        {
            super(new ThreefishEngine(ThreefishEngine.BLOCKSIZE_1024));
        }
    }

    public static class KeyGen_256
        extends BaseKeyGenerator
    {
        public KeyGen_256()
        {
            super("Threefish-256", 256, new CipherKeyGenerator());
        }
    }

    public static class KeyGen_512
        extends BaseKeyGenerator
    {
        public KeyGen_512()
        {
            super("Threefish-512", 512, new CipherKeyGenerator());
        }
    }

    public static class KeyGen_1024
        extends BaseKeyGenerator
    {
        public KeyGen_1024()
        {
            super("Threefish-1024", 1024, new CipherKeyGenerator());
        }
    }

    public static class AlgParams_256
        extends IvAlgorithmParameters
    {
        protected String engineToString()
        {
            return "Threefish-256 IV";
        }
    }

    public static class AlgParams_512
        extends IvAlgorithmParameters
    {
        protected String engineToString()
        {
            return "Threefish-512 IV";
        }
    }

    public static class AlgParams_1024
        extends IvAlgorithmParameters
    {
        protected String engineToString()
        {
            return "Threefish-1024 IV";
        }
    }

    public static class CMAC_256
        extends BaseMac
    {
        public CMAC_256()
        {
            super(new CMac(new ThreefishEngine(256)));
        }
    }

    public static class CMAC_512
        extends BaseMac
    {
        public CMAC_512()
        {
            super(new CMac(new ThreefishEngine(512)));
        }
    }

    public static class CMAC_1024
        extends BaseMac
    {
        public CMAC_1024()
        {
            super(new CMac(new ThreefishEngine(1024)));
        }
    }

    public static class Mappings
        extends AlgorithmProvider
    {
        private static final String PREFIX = Threefish.class.getName();

        public Mappings()
        {
        }

        public void configure(ConfigurableProvider provider)
        {
            provider.addAlgorithm("Mac.Threefish-256CMAC", PREFIX + "$CMAC_256");
            provider.addAlgorithm("Mac.Threefish-512CMAC", PREFIX + "$CMAC_512");
            provider.addAlgorithm("Mac.Threefish-1024CMAC", PREFIX + "$CMAC_1024");

            provider.addAlgorithm("Cipher.Threefish-256", PREFIX + "$ECB_256");
            provider.addAlgorithm("Cipher.Threefish-512", PREFIX + "$ECB_512");
            provider.addAlgorithm("Cipher.Threefish-1024", PREFIX + "$ECB_1024");
            provider.addAlgorithm("KeyGenerator.Threefish-256", PREFIX + "$KeyGen_256");
            provider.addAlgorithm("KeyGenerator.Threefish-512", PREFIX + "$KeyGen_512");
            provider.addAlgorithm("KeyGenerator.Threefish-1024", PREFIX + "$KeyGen_1024");
            provider.addAlgorithm("AlgorithmParameters.Threefish-256", PREFIX + "$AlgParams_256");
            provider.addAlgorithm("AlgorithmParameters.Threefish-512", PREFIX + "$AlgParams_512");
            provider.addAlgorithm("AlgorithmParameters.Threefish-1024", PREFIX + "$AlgParams_1024");
        }
    }
}
