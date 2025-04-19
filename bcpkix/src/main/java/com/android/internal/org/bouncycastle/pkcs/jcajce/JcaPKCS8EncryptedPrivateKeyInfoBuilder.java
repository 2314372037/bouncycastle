package com.android.internal.org.bouncycastle.pkcs.jcajce;

import java.security.PrivateKey;

import com.android.internal.org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import com.android.internal.org.bouncycastle.pkcs.PKCS8EncryptedPrivateKeyInfoBuilder;

public class JcaPKCS8EncryptedPrivateKeyInfoBuilder
    extends PKCS8EncryptedPrivateKeyInfoBuilder
{
    public JcaPKCS8EncryptedPrivateKeyInfoBuilder(PrivateKey privateKey)
    {
         super(PrivateKeyInfo.getInstance(privateKey.getEncoded()));
    }
}
