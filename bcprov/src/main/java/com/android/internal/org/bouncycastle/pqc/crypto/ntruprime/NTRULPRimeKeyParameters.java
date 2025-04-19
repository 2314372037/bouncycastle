package com.android.internal.org.bouncycastle.pqc.crypto.ntruprime;

import com.android.internal.org.bouncycastle.crypto.params.AsymmetricKeyParameter;

public class NTRULPRimeKeyParameters
    extends AsymmetricKeyParameter
{
    private final NTRULPRimeParameters params;

    public NTRULPRimeKeyParameters(boolean privateKey, NTRULPRimeParameters params)
    {
        super(privateKey);
        this.params = params;
    }

    public NTRULPRimeParameters getParameters()
    {
        return params;
    }
}
