package com.android.internal.org.bouncycastle.openssl.jcajce;

import java.security.Provider;

import com.android.internal.org.bouncycastle.jcajce.util.DefaultJcaJceHelper;
import com.android.internal.org.bouncycastle.jcajce.util.JcaJceHelper;
import com.android.internal.org.bouncycastle.jcajce.util.NamedJcaJceHelper;
import com.android.internal.org.bouncycastle.jcajce.util.ProviderJcaJceHelper;
import com.android.internal.org.bouncycastle.openssl.PEMDecryptor;
import com.android.internal.org.bouncycastle.openssl.PEMDecryptorProvider;
import com.android.internal.org.bouncycastle.openssl.PEMException;
import com.android.internal.org.bouncycastle.openssl.PasswordException;

public class JcePEMDecryptorProviderBuilder
{
    private JcaJceHelper helper = new DefaultJcaJceHelper();

    public JcePEMDecryptorProviderBuilder setProvider(Provider provider)
    {
        this.helper = new ProviderJcaJceHelper(provider);

        return this;
    }

    public JcePEMDecryptorProviderBuilder setProvider(String providerName)
    {
        this.helper = new NamedJcaJceHelper(providerName);

        return this;
    }

    public PEMDecryptorProvider build(final char[] password)
    {
        return new PEMDecryptorProvider()
        {
            public PEMDecryptor get(final String dekAlgName)
            {
                return new PEMDecryptor()
                {
                    public byte[] decrypt(byte[] keyBytes, byte[] iv)
                        throws PEMException
                    {
                        if (password == null)
                        {
                            throw new PasswordException("Password is null, but a password is required");
                        }

                        return PEMUtilities.crypt(false, helper, keyBytes, password, dekAlgName, iv);
                    }
                };
            }
        };
    }
}
