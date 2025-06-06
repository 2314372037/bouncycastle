package com.android.internal.org.bouncycastle.pqc.crypto.bike;

import java.security.SecureRandom;

import com.android.internal.org.bouncycastle.crypto.KeyGenerationParameters;

public class BIKEKeyGenerationParameters
    extends KeyGenerationParameters
{
    private BIKEParameters params;

    public BIKEKeyGenerationParameters(
        SecureRandom random,
        BIKEParameters params)
    {
        super(random, 256);
        this.params = params;
    }

    public BIKEParameters getParameters()
    {
        return params;
    }
}
