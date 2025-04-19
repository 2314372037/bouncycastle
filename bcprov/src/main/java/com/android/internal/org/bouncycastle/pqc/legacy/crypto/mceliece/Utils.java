package com.android.internal.org.bouncycastle.pqc.legacy.crypto.mceliece;

import com.android.internal.org.bouncycastle.crypto.Digest;
import com.android.internal.org.bouncycastle.crypto.digests.SHA1Digest;
import com.android.internal.org.bouncycastle.crypto.digests.SHA224Digest;
import com.android.internal.org.bouncycastle.crypto.digests.SHA256Digest;
import com.android.internal.org.bouncycastle.crypto.digests.SHA384Digest;
import com.android.internal.org.bouncycastle.crypto.digests.SHA512Digest;

class Utils
{
    static Digest getDigest(String digestName)
    {
        if (digestName.equals("SHA-1"))
        {
            return new SHA1Digest();
        }
        if (digestName.equals("SHA-224"))
        {
            return new SHA224Digest();
        }
        if (digestName.equals("SHA-256"))
        {
            return new SHA256Digest();
        }
        if (digestName.equals("SHA-384"))
        {
            return new SHA384Digest();
        }
        if (digestName.equals("SHA-512"))
        {
            return new SHA512Digest();
        }

        throw new IllegalArgumentException("unrecognised digest algorithm: " + digestName);
    }
}
