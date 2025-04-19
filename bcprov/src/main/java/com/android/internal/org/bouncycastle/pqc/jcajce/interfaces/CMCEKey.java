package com.android.internal.org.bouncycastle.pqc.jcajce.interfaces;

import java.security.Key;

import com.android.internal.org.bouncycastle.pqc.jcajce.spec.CMCEParameterSpec;

public interface CMCEKey
    extends Key
{
    /**
     * Return the parameters for this key.
     *
     * @return a CMCEParameterSpec
     */
    CMCEParameterSpec getParameterSpec();
}
