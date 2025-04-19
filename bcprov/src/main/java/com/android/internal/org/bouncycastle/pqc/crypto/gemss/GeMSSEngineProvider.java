package com.android.internal.org.bouncycastle.pqc.crypto.gemss;

public interface GeMSSEngineProvider
{
    GeMSSEngine get();

    int getN();
}
