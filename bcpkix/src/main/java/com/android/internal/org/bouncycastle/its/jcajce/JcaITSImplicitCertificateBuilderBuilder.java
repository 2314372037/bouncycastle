package com.android.internal.org.bouncycastle.its.jcajce;

import java.security.Provider;

import com.android.internal.org.bouncycastle.its.ITSCertificate;
import com.android.internal.org.bouncycastle.its.ITSImplicitCertificateBuilder;
import com.android.internal.org.bouncycastle.oer.its.ieee1609dot2.ToBeSignedCertificate;
import com.android.internal.org.bouncycastle.operator.OperatorCreationException;
import com.android.internal.org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;

public class JcaITSImplicitCertificateBuilderBuilder
{
    private final JcaDigestCalculatorProviderBuilder digestCalculatorProviderBuilder = new JcaDigestCalculatorProviderBuilder();

    public JcaITSImplicitCertificateBuilderBuilder setProvider(Provider provider)
    {
        this.digestCalculatorProviderBuilder.setProvider(provider);

        return this;
    }

    public JcaITSImplicitCertificateBuilderBuilder setProvider(String providerName)
    {
        this.digestCalculatorProviderBuilder.setProvider(providerName);

        return this;
    }

    public ITSImplicitCertificateBuilder build(ITSCertificate issuer, ToBeSignedCertificate.Builder tbsCertificate)
        throws OperatorCreationException
    {
        return new ITSImplicitCertificateBuilder(issuer, digestCalculatorProviderBuilder.build(), tbsCertificate);
    }
}
