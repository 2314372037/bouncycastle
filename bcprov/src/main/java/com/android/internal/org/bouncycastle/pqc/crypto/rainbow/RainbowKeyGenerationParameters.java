package com.android.internal.org.bouncycastle.pqc.crypto.rainbow;

import java.security.SecureRandom;

import com.android.internal.org.bouncycastle.crypto.KeyGenerationParameters;

public class RainbowKeyGenerationParameters
    extends KeyGenerationParameters
{
    private RainbowParameters params;

    public RainbowKeyGenerationParameters(
        SecureRandom random,
        RainbowParameters params
    )
    {

        // TODO: actual strength
        super(random, 256);
        this.params = params;
    }

    public RainbowParameters getParameters()
    {
        return params;
    }
}

