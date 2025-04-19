package com.android.internal.org.bouncycastle.pqc.crypto.newhope;

import com.android.internal.org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import com.android.internal.org.bouncycastle.util.Arrays;

public class NHPrivateKeyParameters
    extends AsymmetricKeyParameter
{
    final short[] secData;

    public NHPrivateKeyParameters(short[] secData)
    {
        super(true);

        this.secData = Arrays.clone(secData);
    }

    public short[] getSecData()
    {
        return Arrays.clone(secData);
    }
}
