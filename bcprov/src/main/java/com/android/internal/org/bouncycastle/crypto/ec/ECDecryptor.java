package com.android.internal.org.bouncycastle.crypto.ec;

import com.android.internal.org.bouncycastle.crypto.CipherParameters;
import com.android.internal.org.bouncycastle.math.ec.ECPoint;

public interface ECDecryptor
{
    void init(CipherParameters params);

    ECPoint decrypt(ECPair cipherText);
}
