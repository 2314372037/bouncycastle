package com.android.internal.org.bouncycastle.pqc.jcajce.provider.ntruprime;

import java.security.InvalidAlgorithmParameterException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;

import javax.crypto.KeyGeneratorSpi;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.security.auth.DestroyFailedException;

import com.android.internal.org.bouncycastle.crypto.SecretWithEncapsulation;
import com.android.internal.org.bouncycastle.jcajce.SecretKeyWithEncapsulation;
import com.android.internal.org.bouncycastle.jcajce.spec.KEMExtractSpec;
import com.android.internal.org.bouncycastle.jcajce.spec.KEMGenerateSpec;
import com.android.internal.org.bouncycastle.pqc.crypto.ntruprime.SNTRUPrimeKEMExtractor;
import com.android.internal.org.bouncycastle.pqc.crypto.ntruprime.SNTRUPrimeKEMGenerator;
import com.android.internal.org.bouncycastle.util.Arrays;

public class SNTRUPrimeKeyGeneratorSpi
        extends KeyGeneratorSpi
{
    private KEMGenerateSpec genSpec;
    private SecureRandom random;
    private KEMExtractSpec extSpec;

    protected void engineInit(SecureRandom secureRandom)
    {
        throw new UnsupportedOperationException("Operation not supported");
    }

    protected void engineInit(AlgorithmParameterSpec algorithmParameterSpec, SecureRandom secureRandom)
            throws InvalidAlgorithmParameterException
    {
        this.random = secureRandom;
        if (algorithmParameterSpec instanceof KEMGenerateSpec)
        {
            this.genSpec = (KEMGenerateSpec)algorithmParameterSpec;
            this.extSpec = null;
        }
        else if (algorithmParameterSpec instanceof KEMExtractSpec)
        {
            this.genSpec = null;
            this.extSpec = (KEMExtractSpec)algorithmParameterSpec;
        }
        else
        {
            throw new InvalidAlgorithmParameterException("unknown spec");
        }
    }

    protected void engineInit(int i, SecureRandom secureRandom)
    {
        throw new UnsupportedOperationException("Operation not supported");
    }

    protected SecretKey engineGenerateKey()
    {
        if (genSpec != null)
        {
            BCSNTRUPrimePublicKey pubKey = (BCSNTRUPrimePublicKey)genSpec.getPublicKey();
            SNTRUPrimeKEMGenerator kemGen = new SNTRUPrimeKEMGenerator(random);

            SecretWithEncapsulation secEnc = kemGen.generateEncapsulated(pubKey.getKeyParams());

            SecretKey rv = new SecretKeyWithEncapsulation(new SecretKeySpec(secEnc.getSecret(), genSpec.getKeyAlgorithmName()), secEnc.getEncapsulation());

            try
            {
                secEnc.destroy();
            }
            catch (DestroyFailedException e)
            {
                throw new IllegalStateException("key cleanup failed");
            }

            return rv;
        }
        else
        {
            BCSNTRUPrimePrivateKey privKey = (BCSNTRUPrimePrivateKey)extSpec.getPrivateKey();
            SNTRUPrimeKEMExtractor kemExt = new SNTRUPrimeKEMExtractor(privKey.getKeyParams());

            byte[] encapsulation = extSpec.getEncapsulation();
            byte[] secret = kemExt.extractSecret(encapsulation);

            SecretKey rv = new SecretKeyWithEncapsulation(new SecretKeySpec(secret, extSpec.getKeyAlgorithmName()), encapsulation);

            Arrays.clear(secret);

            return rv;
        }
    }
}
