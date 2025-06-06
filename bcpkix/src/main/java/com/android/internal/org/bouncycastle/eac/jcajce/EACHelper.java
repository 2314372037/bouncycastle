package com.android.internal.org.bouncycastle.eac.jcajce;

import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;

interface EACHelper
{
    KeyFactory createKeyFactory(String type)
        throws NoSuchProviderException, NoSuchAlgorithmException;
}
