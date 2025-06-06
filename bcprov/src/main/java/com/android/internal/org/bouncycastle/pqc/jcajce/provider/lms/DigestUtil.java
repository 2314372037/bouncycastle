package com.android.internal.org.bouncycastle.pqc.jcajce.provider.lms;

import com.android.internal.org.bouncycastle.crypto.Digest;
import com.android.internal.org.bouncycastle.crypto.Xof;

class DigestUtil
{
    public static byte[] getDigestResult(Digest digest)
    {
        byte[] hash = new byte[digest.getDigestSize()];

        if (digest instanceof Xof)
        {
            ((Xof)digest).doFinal(hash, 0, hash.length);
        }
        else
        {
            digest.doFinal(hash, 0);
        }

        return hash;
    }
}
