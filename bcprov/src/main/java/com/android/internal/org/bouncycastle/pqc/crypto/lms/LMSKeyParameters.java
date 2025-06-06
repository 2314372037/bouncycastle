package com.android.internal.org.bouncycastle.pqc.crypto.lms;

import java.io.IOException;

import com.android.internal.org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import com.android.internal.org.bouncycastle.util.Encodable;

public abstract class LMSKeyParameters
    extends AsymmetricKeyParameter
    implements Encodable
{
    protected LMSKeyParameters(boolean isPrivateKey)
    {
        super(isPrivateKey);
    }

    abstract public byte[] getEncoded()
        throws IOException;
}
