package com.android.internal.org.bouncycastle.crypto.util;

import java.security.SecureRandom;

import com.android.internal.org.bouncycastle.asn1.ASN1ObjectIdentifier;
import com.android.internal.org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import com.android.internal.org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import com.android.internal.org.bouncycastle.crypto.CipherKeyGenerator;
import com.android.internal.org.bouncycastle.crypto.KeyGenerationParameters;
import com.android.internal.org.bouncycastle.crypto.generators.DESKeyGenerator;
import com.android.internal.org.bouncycastle.crypto.generators.DESedeKeyGenerator;
import com.android.internal.org.bouncycastle.internal.asn1.kisa.KISAObjectIdentifiers;
import com.android.internal.org.bouncycastle.internal.asn1.ntt.NTTObjectIdentifiers;
import com.android.internal.org.bouncycastle.internal.asn1.oiw.OIWObjectIdentifiers;

/**
 * Factory methods for generating secret key generators for symmetric ciphers.
 */
public class CipherKeyGeneratorFactory
{
    private CipherKeyGeneratorFactory()
    {
    }

    /**
     * Create a key generator for the passed in Object Identifier.
     *
     * @param algorithm the Object Identifier indicating the algorithn the generator is for.
     * @param random a source of random to initialise the generator with.
     * @return an initialised CipherKeyGenerator.
     * @throws IllegalArgumentException if the algorithm cannot be identified.
     */
    public static CipherKeyGenerator createKeyGenerator(ASN1ObjectIdentifier algorithm, SecureRandom random)
        throws IllegalArgumentException
    {
        if (NISTObjectIdentifiers.id_aes128_CBC.equals(algorithm))
        {
            return createCipherKeyGenerator(random, 128);
        }
        else if (NISTObjectIdentifiers.id_aes192_CBC.equals(algorithm))
        {
            return createCipherKeyGenerator(random, 192);
        }
        else if (NISTObjectIdentifiers.id_aes256_CBC.equals(algorithm))
        {
            return createCipherKeyGenerator(random, 256);
        }
        else if (NISTObjectIdentifiers.id_aes128_GCM.equals(algorithm))
        {
            return createCipherKeyGenerator(random, 128);
        }
        else if (NISTObjectIdentifiers.id_aes192_GCM.equals(algorithm))
        {
            return createCipherKeyGenerator(random, 192);
        }
        else if (NISTObjectIdentifiers.id_aes256_GCM.equals(algorithm))
        {
            return createCipherKeyGenerator(random, 256);
        }
        else if (NISTObjectIdentifiers.id_aes128_CCM.equals(algorithm))
        {
            return createCipherKeyGenerator(random, 128);
        }
        else if (NISTObjectIdentifiers.id_aes192_CCM.equals(algorithm))
        {
            return createCipherKeyGenerator(random, 192);
        }
        else if (NISTObjectIdentifiers.id_aes256_CCM.equals(algorithm))
        {
            return createCipherKeyGenerator(random, 256);
        }
        else if (PKCSObjectIdentifiers.des_EDE3_CBC.equals(algorithm))
        {
            DESedeKeyGenerator keyGen = new DESedeKeyGenerator();

            keyGen.init(new KeyGenerationParameters(random, 192));

            return keyGen;
        }
        else if (NTTObjectIdentifiers.id_camellia128_cbc.equals(algorithm))
        {
            return createCipherKeyGenerator(random, 128);
        }
        else if (NTTObjectIdentifiers.id_camellia192_cbc.equals(algorithm))
        {
            return createCipherKeyGenerator(random, 192);
        }
        else if (NTTObjectIdentifiers.id_camellia256_cbc.equals(algorithm))
        {
            return createCipherKeyGenerator(random, 256);
        }
        else if (KISAObjectIdentifiers.id_seedCBC.equals(algorithm))
        {
            return createCipherKeyGenerator(random, 128);
        }
        else if (AlgorithmIdentifierFactory.CAST5_CBC.equals(algorithm))
        {
            return createCipherKeyGenerator(random, 128);
        }
        else if (OIWObjectIdentifiers.desCBC.equals(algorithm))
        {
            DESKeyGenerator keyGen = new DESKeyGenerator();

            keyGen.init(new KeyGenerationParameters(random, 64));

            return keyGen;
        }
        else if (PKCSObjectIdentifiers.rc4.equals(algorithm))
        {
            return createCipherKeyGenerator(random, 128);
        }
        else if (PKCSObjectIdentifiers.RC2_CBC.equals(algorithm))
        {
            return createCipherKeyGenerator(random, 128);
        }
        else
        {
            throw new IllegalArgumentException("cannot recognise cipher: " + algorithm);
        }
    }

    private static CipherKeyGenerator createCipherKeyGenerator(SecureRandom random, int keySize)
    {
        CipherKeyGenerator keyGen = new CipherKeyGenerator();

        keyGen.init(new KeyGenerationParameters(random, keySize));

        return keyGen;
    }
}
