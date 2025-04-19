package com.android.internal.org.bouncycastle.pqc.crypto.bike;

import com.android.internal.org.bouncycastle.util.Arrays;

public class BIKEPublicKeyParameters
    extends BIKEKeyParameters
{
    byte[] publicKey;

    /**
     * Constructor.
     *
     * @param publicKey byte
     */
    public BIKEPublicKeyParameters(BIKEParameters params, byte[] publicKey)
    {
        super(false, params);
        this.publicKey = Arrays.clone(publicKey);
    }

    public byte[] getEncoded()
    {
        return Arrays.clone(publicKey);
    }
}
