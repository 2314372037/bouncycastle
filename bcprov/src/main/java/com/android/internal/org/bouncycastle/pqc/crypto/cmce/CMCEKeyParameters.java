package com.android.internal.org.bouncycastle.pqc.crypto.cmce;

import com.android.internal.org.bouncycastle.crypto.params.AsymmetricKeyParameter;

public class CMCEKeyParameters
    extends AsymmetricKeyParameter
{
    private CMCEParameters params;

    public CMCEKeyParameters(
        boolean isPrivate,
        CMCEParameters params)
    {
        super(isPrivate);
        this.params = params;
    }

    public CMCEParameters getParameters()
    {
        return params;
    }

}
