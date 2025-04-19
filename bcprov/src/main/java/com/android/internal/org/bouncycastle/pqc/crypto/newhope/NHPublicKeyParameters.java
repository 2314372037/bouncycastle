package com.android.internal.org.bouncycastle.pqc.crypto.newhope;

import com.android.internal.org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import com.android.internal.org.bouncycastle.util.Arrays;

public class NHPublicKeyParameters
    extends AsymmetricKeyParameter
{
    final byte[] pubData;

    public NHPublicKeyParameters(byte[] pubData)
    {
        super(false);
        this.pubData = Arrays.clone(pubData);
    }

    /**
     * Return the public key data.
     *
     * @return the public key values.
     */
    public byte[] getPubData()
    {
        return Arrays.clone(pubData);
    }
}
