package com.android.internal.org.bouncycastle.crypto;

import com.android.internal.org.bouncycastle.crypto.digests.EncodableDigest;
import com.android.internal.org.bouncycastle.util.Memoable;

/**
 * Extended digest which provides the ability to store state and
 * provide an encoding.
 */
public interface SavableDigest
    extends ExtendedDigest, EncodableDigest, Memoable
{
}
