package com.android.internal.org.bouncycastle.pqc.jcajce.interfaces;

import java.security.Key;

import com.android.internal.org.bouncycastle.pqc.jcajce.spec.PicnicParameterSpec;

public interface PicnicKey
    extends Key
{
    /**
     * Return the parameters for this key.
     *
     * @return a PcnicParameterSpec
     */
    PicnicParameterSpec getParameterSpec();
}
