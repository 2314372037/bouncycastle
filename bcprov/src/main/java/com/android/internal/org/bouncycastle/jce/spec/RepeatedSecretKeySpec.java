package com.android.internal.org.bouncycastle.jce.spec;

/**
 * A simple object to indicate that a symmetric cipher should reuse the
 * last key provided.
 * @deprecated use super class com.android.internal.org.bouncycastle.jcajce.spec.RepeatedSecretKeySpec
 */
public class RepeatedSecretKeySpec
    extends com.android.internal.org.bouncycastle.jcajce.spec.RepeatedSecretKeySpec
{
    private String algorithm;

    public RepeatedSecretKeySpec(String algorithm)
    {
        super(algorithm);
    }
}
