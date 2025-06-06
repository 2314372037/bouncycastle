package com.android.internal.org.bouncycastle.pqc.crypto.gemss;

import com.android.internal.org.bouncycastle.crypto.params.AsymmetricKeyParameter;

public class GeMSSKeyParameters
    extends AsymmetricKeyParameter
{
    final GeMSSParameters parameters;

    protected GeMSSKeyParameters(boolean isPrivate, GeMSSParameters parameters)
    {
        super(isPrivate);
        this.parameters = parameters;
    }

    public GeMSSParameters getParameters()
    {
        return parameters;
    }
}
