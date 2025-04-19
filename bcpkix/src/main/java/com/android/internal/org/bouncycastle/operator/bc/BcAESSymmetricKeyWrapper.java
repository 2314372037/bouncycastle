package com.android.internal.org.bouncycastle.operator.bc;

import com.android.internal.org.bouncycastle.crypto.engines.AESWrapEngine;
import com.android.internal.org.bouncycastle.crypto.params.KeyParameter;

public class BcAESSymmetricKeyWrapper
    extends BcSymmetricKeyWrapper
{
    public BcAESSymmetricKeyWrapper(KeyParameter wrappingKey)
    {
        super(AESUtil.determineKeyEncAlg(wrappingKey), new AESWrapEngine(), wrappingKey);
    }
}
