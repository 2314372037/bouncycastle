package com.android.internal.org.bouncycastle.pqc.crypto.saber;

import com.android.internal.org.bouncycastle.crypto.params.AsymmetricKeyParameter;

public class SABERKeyParameters
    extends AsymmetricKeyParameter
{
    private SABERParameters params;
    public SABERKeyParameters(
            boolean isPrivate,
            SABERParameters params)
    {
        super(isPrivate);
        this.params = params;
    }

    public SABERParameters getParameters()
    {
        return params;
    }
}
