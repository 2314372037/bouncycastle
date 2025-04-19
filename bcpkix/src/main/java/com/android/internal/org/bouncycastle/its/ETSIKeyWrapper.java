package com.android.internal.org.bouncycastle.its;

import com.android.internal.org.bouncycastle.oer.its.ieee1609dot2.EncryptedDataEncryptionKey;

public interface ETSIKeyWrapper
{
    EncryptedDataEncryptionKey wrap(byte[] secretKey);
}
