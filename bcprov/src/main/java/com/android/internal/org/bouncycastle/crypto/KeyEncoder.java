package com.android.internal.org.bouncycastle.crypto;

import com.android.internal.org.bouncycastle.crypto.params.AsymmetricKeyParameter;

public interface KeyEncoder
{
    byte[] getEncoded(AsymmetricKeyParameter keyParameter);
}
