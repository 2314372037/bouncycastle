package com.android.internal.org.bouncycastle.pqc.crypto.xwing;

import java.security.SecureRandom;

import com.android.internal.org.bouncycastle.crypto.KeyGenerationParameters;

public class XWingKeyGenerationParameters
    extends KeyGenerationParameters
{
    public XWingKeyGenerationParameters(SecureRandom random)
    {
        super(random, 128);
    }
}
