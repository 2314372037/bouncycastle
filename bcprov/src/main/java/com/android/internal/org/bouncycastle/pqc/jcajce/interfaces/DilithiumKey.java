package com.android.internal.org.bouncycastle.pqc.jcajce.interfaces;

import java.security.Key;

import com.android.internal.org.bouncycastle.pqc.jcajce.spec.DilithiumParameterSpec;

public interface DilithiumKey
    extends Key
{
    /**
     * Return the parameters for this key.
     *
     * @return a DilithiumParameterSpec
     */
    DilithiumParameterSpec getParameterSpec();
}
