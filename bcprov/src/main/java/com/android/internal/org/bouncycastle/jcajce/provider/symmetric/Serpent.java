package com.android.internal.org.bouncycastle.jcajce.provider.symmetric;

import com.android.internal.org.bouncycastle.crypto.BlockCipher;
import com.android.internal.org.bouncycastle.crypto.BufferedBlockCipher;
import com.android.internal.org.bouncycastle.crypto.CipherKeyGenerator;
import com.android.internal.org.bouncycastle.crypto.engines.SerpentEngine;
import com.android.internal.org.bouncycastle.crypto.engines.TnepresEngine;
import com.android.internal.org.bouncycastle.crypto.generators.Poly1305KeyGenerator;
import com.android.internal.org.bouncycastle.crypto.macs.GMac;
import com.android.internal.org.bouncycastle.crypto.modes.CBCBlockCipher;
import com.android.internal.org.bouncycastle.crypto.modes.CFBBlockCipher;
import com.android.internal.org.bouncycastle.crypto.modes.GCMBlockCipher;
import com.android.internal.org.bouncycastle.crypto.modes.OFBBlockCipher;
import com.android.internal.org.bouncycastle.internal.asn1.gnu.GNUObjectIdentifiers;
import com.android.internal.org.bouncycastle.jcajce.provider.config.ConfigurableProvider;
import com.android.internal.org.bouncycastle.jcajce.provider.symmetric.util.BaseBlockCipher;
import com.android.internal.org.bouncycastle.jcajce.provider.symmetric.util.BaseKeyGenerator;
import com.android.internal.org.bouncycastle.jcajce.provider.symmetric.util.BaseMac;
import com.android.internal.org.bouncycastle.jcajce.provider.symmetric.util.BlockCipherProvider;
import com.android.internal.org.bouncycastle.jcajce.provider.symmetric.util.IvAlgorithmParameters;

public final class Serpent
{
    private Serpent()
    {
    }
    
    public static class ECB
        extends BaseBlockCipher
    {
        public ECB()
        {
            super(new BlockCipherProvider()
            {
                public BlockCipher get()
                {
                    return new SerpentEngine();
                }
            });
        }
    }

    public static class TECB
        extends BaseBlockCipher
    {
        public TECB()
        {
            super(new BlockCipherProvider()
            {
                public BlockCipher get()
                {
                    return new TnepresEngine();
                }
            });
        }
    }

    public static class CBC
        extends BaseBlockCipher
    {
        public CBC()
        {
            super(new CBCBlockCipher(new SerpentEngine()), 128);
        }
    }

    public static class CFB
        extends BaseBlockCipher
    {
        public CFB()
        {
            super(new BufferedBlockCipher(new CFBBlockCipher(new SerpentEngine(), 128)), 128);
        }
    }

    public static class OFB
        extends BaseBlockCipher
    {
        public OFB()
        {
            super(new BufferedBlockCipher(new OFBBlockCipher(new SerpentEngine(), 128)), 128);
        }
    }

    public static class KeyGen
        extends BaseKeyGenerator
    {
        public KeyGen()
        {
            super("Serpent", 192, new CipherKeyGenerator());
        }
    }

    public static class TKeyGen
        extends BaseKeyGenerator
    {
        public TKeyGen()
        {
            super("Tnepres", 192, new CipherKeyGenerator());
        }
    }

    public static class SerpentGMAC
        extends BaseMac
    {
        public SerpentGMAC()
        {
            super(new GMac(new GCMBlockCipher(new SerpentEngine())));
        }
    }

    public static class TSerpentGMAC
        extends BaseMac
    {
        public TSerpentGMAC()
        {
            super(new GMac(new GCMBlockCipher(new TnepresEngine())));
        }
    }

    public static class Poly1305
        extends BaseMac
    {
        public Poly1305()
        {
            super(new com.android.internal.org.bouncycastle.crypto.macs.Poly1305(new SerpentEngine()));
        }
    }

    public static class Poly1305KeyGen
        extends BaseKeyGenerator
    {
        public Poly1305KeyGen()
        {
            super("Poly1305-Serpent", 256, new Poly1305KeyGenerator());
        }
    }

    public static class AlgParams
        extends IvAlgorithmParameters
    {
        protected String engineToString()
        {
            return "Serpent IV";
        }
    }

    public static class TAlgParams
        extends IvAlgorithmParameters
    {
        protected String engineToString()
        {
            return "Tnepres IV";
        }
    }

    public static class Mappings
        extends SymmetricAlgorithmProvider
    {
        private static final String PREFIX = Serpent.class.getName();

        public Mappings()
        {
        }

        public void configure(ConfigurableProvider provider)
        {

            provider.addAlgorithm("Cipher.Serpent", PREFIX + "$ECB");
            provider.addAlgorithm("KeyGenerator.Serpent", PREFIX + "$KeyGen");
            provider.addAlgorithm("AlgorithmParameters.Serpent", PREFIX + "$AlgParams");

            provider.addAlgorithm("Cipher.Tnepres", PREFIX + "$TECB");
            provider.addAlgorithm("KeyGenerator.Tnepres", PREFIX + "$TKeyGen");
            provider.addAlgorithm("AlgorithmParameters.Tnepres", PREFIX + "$TAlgParams");

            provider.addAlgorithm("Cipher", GNUObjectIdentifiers.Serpent_128_ECB, PREFIX + "$ECB");
            provider.addAlgorithm("Cipher", GNUObjectIdentifiers.Serpent_192_ECB, PREFIX + "$ECB");
            provider.addAlgorithm("Cipher", GNUObjectIdentifiers.Serpent_256_ECB, PREFIX + "$ECB");

            provider.addAlgorithm("Cipher", GNUObjectIdentifiers.Serpent_128_CBC, PREFIX + "$CBC");
            provider.addAlgorithm("Cipher", GNUObjectIdentifiers.Serpent_192_CBC, PREFIX + "$CBC");
            provider.addAlgorithm("Cipher", GNUObjectIdentifiers.Serpent_256_CBC, PREFIX + "$CBC");

            provider.addAlgorithm("Cipher", GNUObjectIdentifiers.Serpent_128_CFB, PREFIX + "$CFB");
            provider.addAlgorithm("Cipher", GNUObjectIdentifiers.Serpent_192_CFB, PREFIX + "$CFB");
            provider.addAlgorithm("Cipher", GNUObjectIdentifiers.Serpent_256_CFB, PREFIX + "$CFB");

            provider.addAlgorithm("Cipher", GNUObjectIdentifiers.Serpent_128_OFB, PREFIX + "$OFB");
            provider.addAlgorithm("Cipher", GNUObjectIdentifiers.Serpent_192_OFB, PREFIX + "$OFB");
            provider.addAlgorithm("Cipher", GNUObjectIdentifiers.Serpent_256_OFB, PREFIX + "$OFB");

            addGMacAlgorithm(provider, "SERPENT", PREFIX + "$SerpentGMAC", PREFIX + "$KeyGen");
            addGMacAlgorithm(provider, "TNEPRES", PREFIX + "$TSerpentGMAC", PREFIX + "$TKeyGen");
            addPoly1305Algorithm(provider, "SERPENT", PREFIX + "$Poly1305", PREFIX + "$Poly1305KeyGen");
        }
    }
}
