package com.android.internal.org.bouncycastle.pqc.crypto.sphincsplus;

interface SPHINCSPlusEngineProvider
{
    int getN();

    SPHINCSPlusEngine get();
}
