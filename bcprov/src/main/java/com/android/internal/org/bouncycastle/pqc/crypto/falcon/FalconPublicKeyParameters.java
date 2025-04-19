package com.android.internal.org.bouncycastle.pqc.crypto.falcon;

import com.android.internal.org.bouncycastle.util.Arrays;

public class FalconPublicKeyParameters
    extends FalconKeyParameters
{
    private byte[] H;

    public FalconPublicKeyParameters(FalconParameters parameters, byte[] H)
    {
        super(false, parameters);
        this.H = Arrays.clone(H);
    }

    public byte[] getH()
    {
        return Arrays.clone(H);
    }
}
