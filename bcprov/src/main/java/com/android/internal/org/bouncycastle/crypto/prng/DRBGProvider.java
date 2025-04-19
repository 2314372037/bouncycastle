package com.android.internal.org.bouncycastle.crypto.prng;

import com.android.internal.org.bouncycastle.crypto.prng.drbg.SP80090DRBG;

interface DRBGProvider
{
    String getAlgorithm();

    SP80090DRBG get(EntropySource entropySource);
}
