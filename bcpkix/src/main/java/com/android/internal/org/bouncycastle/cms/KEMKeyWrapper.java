package com.android.internal.org.bouncycastle.cms;

import com.android.internal.org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import com.android.internal.org.bouncycastle.operator.AsymmetricKeyWrapper;

public abstract class KEMKeyWrapper
    extends AsymmetricKeyWrapper
{
    protected KEMKeyWrapper(AlgorithmIdentifier algorithmId)
    {
        super(algorithmId);
    }

    public abstract byte[] getEncapsulation();

    public abstract AlgorithmIdentifier getKdfAlgorithmIdentifier();

    public abstract int getKekLength();

    public abstract AlgorithmIdentifier getWrapAlgorithmIdentifier();
}
