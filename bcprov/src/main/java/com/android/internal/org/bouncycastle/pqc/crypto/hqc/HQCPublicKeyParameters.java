package com.android.internal.org.bouncycastle.pqc.crypto.hqc;

import com.android.internal.org.bouncycastle.util.Arrays;

public class HQCPublicKeyParameters
    extends HQCKeyParameters
{
    private byte[] pk;

    public HQCPublicKeyParameters(HQCParameters params, byte[] pk)
    {
        super(true, params);
        this.pk = Arrays.clone(pk);
    }

    public byte[] getPublicKey()
    {
        return Arrays.clone(pk);
    }

    public byte[] getEncoded()
    {
        return getPublicKey();
    }
}
