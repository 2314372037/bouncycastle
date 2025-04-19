package com.android.internal.org.bouncycastle.pqc.crypto.xwing;

import com.android.internal.org.bouncycastle.crypto.params.AsymmetricKeyParameter;

public class XWingKeyParameters
    extends AsymmetricKeyParameter
{
    XWingKeyParameters(
        boolean isPrivate)
    {
        super(isPrivate);
    }
}
