package com.android.internal.org.bouncycastle.pqc.legacy.crypto.mceliece;

import com.android.internal.org.bouncycastle.crypto.params.AsymmetricKeyParameter;


public class McElieceCCA2KeyParameters
    extends AsymmetricKeyParameter
{
    private String params;

    public McElieceCCA2KeyParameters(
        boolean isPrivate,
        String params)
    {
        super(isPrivate);
        this.params = params;
    }


    public String getDigest()
    {
        return params;
    }

}
