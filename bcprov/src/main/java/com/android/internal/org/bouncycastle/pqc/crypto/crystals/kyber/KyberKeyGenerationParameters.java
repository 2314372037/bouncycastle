package com.android.internal.org.bouncycastle.pqc.crypto.crystals.kyber;

import java.security.SecureRandom;

import com.android.internal.org.bouncycastle.crypto.KeyGenerationParameters;

public class KyberKeyGenerationParameters
    extends KeyGenerationParameters
{
    private final KyberParameters params;

    public KyberKeyGenerationParameters(
        SecureRandom random,
        KyberParameters kyberParameters)
    {
        super(random, 256);
        this.params = kyberParameters;
    }

    public KyberParameters getParameters()
    {
        return params;
    }
}
