package com.android.internal.org.bouncycastle.pqc.legacy.crypto.gmss;

import java.security.SecureRandom;

import com.android.internal.org.bouncycastle.crypto.KeyGenerationParameters;

public class GMSSKeyGenerationParameters
    extends KeyGenerationParameters
{

    private GMSSParameters params;

    public GMSSKeyGenerationParameters(
        SecureRandom random,
        GMSSParameters params)
    {
        // XXX key size?
        super(random, 1);
        this.params = params;
    }

    public GMSSParameters getParameters()
    {
        return params;
    }
}
