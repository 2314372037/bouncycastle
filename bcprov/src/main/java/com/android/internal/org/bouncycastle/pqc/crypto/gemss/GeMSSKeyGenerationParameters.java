package com.android.internal.org.bouncycastle.pqc.crypto.gemss;

import java.security.SecureRandom;

import com.android.internal.org.bouncycastle.crypto.KeyGenerationParameters;

public class GeMSSKeyGenerationParameters
    extends KeyGenerationParameters
{
    final GeMSSParameters parameters;

    public GeMSSKeyGenerationParameters(SecureRandom random, GeMSSParameters parameters)
    {
        super(random, -1);
        this.parameters = parameters;
    }

    public GeMSSParameters getParameters()
    {
        return parameters;
    }
}
