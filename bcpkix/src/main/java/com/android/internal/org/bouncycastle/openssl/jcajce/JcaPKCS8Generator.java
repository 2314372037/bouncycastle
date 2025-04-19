package com.android.internal.org.bouncycastle.openssl.jcajce;

import java.security.PrivateKey;

import com.android.internal.org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import com.android.internal.org.bouncycastle.openssl.PKCS8Generator;
import com.android.internal.org.bouncycastle.operator.OutputEncryptor;
import com.android.internal.org.bouncycastle.util.io.pem.PemGenerationException;

public class JcaPKCS8Generator
    extends PKCS8Generator
{
    public JcaPKCS8Generator(PrivateKey key, OutputEncryptor encryptor)
         throws PemGenerationException
    {
         super(PrivateKeyInfo.getInstance(key.getEncoded()), encryptor);
    }
}
