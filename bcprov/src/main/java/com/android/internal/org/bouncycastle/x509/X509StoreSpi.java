package com.android.internal.org.bouncycastle.x509;

import com.android.internal.org.bouncycastle.util.Selector;

import java.util.Collection;

public abstract class X509StoreSpi
{
    public abstract void engineInit(X509StoreParameters parameters);

    public abstract Collection engineGetMatches(Selector selector);
}
