package com.android.internal.org.bouncycastle.pqc.crypto.picnic;

import com.android.internal.org.bouncycastle.util.Arrays;

public class PicnicPrivateKeyParameters
    extends PicnicKeyParameters
{
    private final byte[] privateKey;

    public PicnicPrivateKeyParameters(PicnicParameters parameters, byte[] skEncoded)
    {
        super(true, parameters);
        privateKey = Arrays.clone(skEncoded);
    }

    public byte[] getEncoded()
    {
        return Arrays.clone(privateKey);
    }

}
