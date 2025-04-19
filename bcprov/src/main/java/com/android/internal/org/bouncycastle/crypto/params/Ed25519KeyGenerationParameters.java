package com.android.internal.org.bouncycastle.crypto.params;

import java.security.SecureRandom;

import com.android.internal.org.bouncycastle.crypto.KeyGenerationParameters;

public class Ed25519KeyGenerationParameters
    extends KeyGenerationParameters
{
    public Ed25519KeyGenerationParameters(SecureRandom random)
    {
        super(random, 256);
    }
}
