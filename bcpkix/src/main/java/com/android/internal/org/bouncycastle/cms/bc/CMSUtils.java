package com.android.internal.org.bouncycastle.cms.bc;

import com.android.internal.org.bouncycastle.crypto.CipherParameters;
import com.android.internal.org.bouncycastle.crypto.params.KeyParameter;
import com.android.internal.org.bouncycastle.operator.GenericKey;

class CMSUtils
{
    static CipherParameters getBcKey(GenericKey key)
    {
        if (key.getRepresentation() instanceof CipherParameters)
        {
            return (CipherParameters)key.getRepresentation();
        }

        if (key.getRepresentation() instanceof byte[])
        {
            return new KeyParameter((byte[])key.getRepresentation());
        }

        throw new IllegalArgumentException("unknown generic key type");
    }
}
