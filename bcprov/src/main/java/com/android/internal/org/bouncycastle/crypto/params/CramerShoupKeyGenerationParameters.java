package com.android.internal.org.bouncycastle.crypto.params;

import java.security.SecureRandom;

import com.android.internal.org.bouncycastle.crypto.KeyGenerationParameters;

public class CramerShoupKeyGenerationParameters
    extends KeyGenerationParameters
{

    private CramerShoupParameters params;

    public CramerShoupKeyGenerationParameters(SecureRandom random, CramerShoupParameters params)
    {
        super(random, getStrength(params));

        this.params = params;
    }

    public CramerShoupParameters getParameters()
    {
        return params;
    }

    static int getStrength(CramerShoupParameters params)
    {
        return params.getP().bitLength();
    }
}
