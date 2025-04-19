package com.android.internal.org.bouncycastle.operator;

import com.android.internal.org.bouncycastle.asn1.x509.AlgorithmIdentifier;

public abstract class SymmetricKeyUnwrapper
    implements KeyUnwrapper
{
    private AlgorithmIdentifier algorithmId;

    protected SymmetricKeyUnwrapper(AlgorithmIdentifier algorithmId)
    {
        this.algorithmId = algorithmId;
    }

    public AlgorithmIdentifier getAlgorithmIdentifier()
    {
        return algorithmId;
    }
}
