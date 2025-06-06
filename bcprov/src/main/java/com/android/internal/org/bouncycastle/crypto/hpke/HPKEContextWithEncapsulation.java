package com.android.internal.org.bouncycastle.crypto.hpke;

import com.android.internal.org.bouncycastle.util.Arrays;

public class HPKEContextWithEncapsulation
    extends HPKEContext
{
    final byte[] encapsulation;

    public HPKEContextWithEncapsulation(HPKEContext context, byte[] encapsulation)
    {
        super(context.aead, context.hkdf, context.exporterSecret, context.suiteId);
        this.encapsulation = encapsulation;
    }

    public byte[] getEncapsulation()
    {
        return Arrays.clone(encapsulation);
    }
}
