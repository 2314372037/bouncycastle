package com.android.internal.org.bouncycastle.crypto.ec;

import com.android.internal.org.bouncycastle.crypto.CipherParameters;
import com.android.internal.org.bouncycastle.math.ec.ECPoint;

public interface ECEncryptor
{
    void init(CipherParameters params);

    ECPair encrypt(ECPoint point);
}
