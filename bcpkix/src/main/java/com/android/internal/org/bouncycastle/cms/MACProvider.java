package com.android.internal.org.bouncycastle.cms;

import java.io.IOException;

interface MACProvider
{
    byte[] getMAC();

    void init() throws IOException;
}

