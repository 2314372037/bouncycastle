package com.android.internal.org.bouncycastle.crypto.params;

import java.security.SecureRandom;

import com.android.internal.org.bouncycastle.crypto.KeyGenerationParameters;

public class X25519KeyGenerationParameters
    extends KeyGenerationParameters
{
    public X25519KeyGenerationParameters(SecureRandom random)
    {
        super(random, 255);
    }
}
