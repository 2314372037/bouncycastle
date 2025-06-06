package com.android.internal.org.bouncycastle.pqc.crypto.crystals.kyber;

import com.android.internal.org.bouncycastle.crypto.params.AsymmetricKeyParameter;

public class KyberKeyParameters
    extends AsymmetricKeyParameter
{
    private KyberParameters params;

    public KyberKeyParameters(
        boolean isPrivate,
        KyberParameters params)
    {
        super(isPrivate);
        this.params = params;
    }

    public KyberParameters getParameters()
    {
        return params;
    }

}
