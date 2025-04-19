package com.android.internal.org.bouncycastle.operator.bc;

import com.android.internal.org.bouncycastle.crypto.engines.AESWrapEngine;
import com.android.internal.org.bouncycastle.crypto.params.KeyParameter;

public class BcAESSymmetricKeyUnwrapper
    extends BcSymmetricKeyUnwrapper
{
    public BcAESSymmetricKeyUnwrapper(KeyParameter wrappingKey)
    {
        super(AESUtil.determineKeyEncAlg(wrappingKey), new AESWrapEngine(), wrappingKey);
    }
}
