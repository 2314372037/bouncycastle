package com.android.internal.org.bouncycastle.crypto.engines;

public class AESWrapPadEngine
    extends RFC5649WrapEngine
{
    public AESWrapPadEngine()
    {
        super(AESEngine.newInstance());
    }
}
