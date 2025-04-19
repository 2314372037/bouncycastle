package com.android.internal.org.bouncycastle.crypto.ec;

import com.android.internal.org.bouncycastle.crypto.CipherParameters;

public interface ECPairTransform
{
    void init(CipherParameters params);

    ECPair transform(ECPair cipherText);
}
