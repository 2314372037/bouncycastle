package com.android.internal.org.bouncycastle.crypto.modes;

import com.android.internal.org.bouncycastle.crypto.BlockCipher;
import com.android.internal.org.bouncycastle.crypto.MultiBlockCipher;
import com.android.internal.org.bouncycastle.crypto.SkippingStreamCipher;

public interface CTRModeCipher
    extends MultiBlockCipher, SkippingStreamCipher
{
    /**
     * return the underlying block cipher that we are wrapping.
     *
     * @return the underlying block cipher that we are wrapping.
     */
    BlockCipher getUnderlyingCipher();
}
