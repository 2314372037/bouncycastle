package com.android.internal.org.bouncycastle.pqc.crypto.crystals.dilithium;

import java.security.SecureRandom;

import com.android.internal.org.bouncycastle.crypto.KeyGenerationParameters;

public class DilithiumKeyGenerationParameters
    extends KeyGenerationParameters
{
    private final DilithiumParameters params;

    public DilithiumKeyGenerationParameters(
        SecureRandom random,
        DilithiumParameters dilithiumParameters)
    {
        super(random, 256);
        this.params = dilithiumParameters;
    }

    public DilithiumParameters getParameters()
    {
        return params;
    }
}
