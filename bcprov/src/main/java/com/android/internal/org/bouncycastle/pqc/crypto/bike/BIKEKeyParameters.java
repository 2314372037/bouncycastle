package com.android.internal.org.bouncycastle.pqc.crypto.bike;

import com.android.internal.org.bouncycastle.crypto.params.AsymmetricKeyParameter;

public class BIKEKeyParameters
    extends AsymmetricKeyParameter
{
    private BIKEParameters params;

    public BIKEKeyParameters(
        boolean isPrivate,
        BIKEParameters params)
    {
        super(isPrivate);
        this.params = params;
    }

    public BIKEParameters getParameters()
    {
        return params;
    }
}
