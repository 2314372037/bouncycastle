package com.android.internal.org.bouncycastle.crypto.params;

import java.security.SecureRandom;

import com.android.internal.org.bouncycastle.crypto.KeyGenerationParameters;

public class X448KeyGenerationParameters
    extends KeyGenerationParameters
{
    public X448KeyGenerationParameters(SecureRandom random)
    {
        super(random, 448);
    }
}
