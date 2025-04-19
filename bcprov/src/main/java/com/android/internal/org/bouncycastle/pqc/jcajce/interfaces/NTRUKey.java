package com.android.internal.org.bouncycastle.pqc.jcajce.interfaces;

import java.security.Key;

import com.android.internal.org.bouncycastle.pqc.jcajce.spec.NTRUParameterSpec;

public interface NTRUKey
    extends Key
{
    /**
     * Return the parameters for this key.
     *
     * @return a NTRUParameterSpec
     */
    NTRUParameterSpec getParameterSpec();
}
