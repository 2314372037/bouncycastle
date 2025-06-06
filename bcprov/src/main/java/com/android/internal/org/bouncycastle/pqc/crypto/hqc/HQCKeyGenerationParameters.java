package com.android.internal.org.bouncycastle.pqc.crypto.hqc;

import java.security.SecureRandom;

import com.android.internal.org.bouncycastle.crypto.KeyGenerationParameters;

public class HQCKeyGenerationParameters
    extends KeyGenerationParameters
{
    private HQCParameters params;

    public HQCKeyGenerationParameters(
        SecureRandom random,
        HQCParameters params)
    {
        super(random, 256);
        this.params = params;
    }

    public HQCParameters getParameters()
    {
        return params;
    }
}
