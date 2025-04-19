package com.android.internal.org.bouncycastle.crypto.modes.kgcm;

public interface KGCMMultiplier
{
    void init(long[] H);
    void multiplyH(long[] z);
}
