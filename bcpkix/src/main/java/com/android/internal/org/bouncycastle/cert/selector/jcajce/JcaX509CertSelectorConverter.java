package com.android.internal.org.bouncycastle.cert.selector.jcajce;

import java.io.IOException;
import java.math.BigInteger;
import java.security.cert.X509CertSelector;

import com.android.internal.org.bouncycastle.asn1.DEROctetString;
import com.android.internal.org.bouncycastle.asn1.x500.X500Name;
import com.android.internal.org.bouncycastle.cert.selector.X509CertificateHolderSelector;
import com.android.internal.org.bouncycastle.util.Exceptions;

public class JcaX509CertSelectorConverter
{
    public JcaX509CertSelectorConverter()
    {
    }

    protected X509CertSelector doConversion(X500Name issuer, BigInteger serialNumber, byte[] subjectKeyIdentifier)
    {
        X509CertSelector selector = new X509CertSelector();

        if (issuer != null)
        {
            try
            {
                selector.setIssuer(issuer.getEncoded());
            }
            catch (IOException e)
            {
                throw Exceptions.illegalArgumentException("unable to convert issuer: " + e.getMessage(), e);
            }
        }

        if (serialNumber != null)
        {
            selector.setSerialNumber(serialNumber);
        }

        if (subjectKeyIdentifier != null)
        {
            try
            {
                selector.setSubjectKeyIdentifier(new DEROctetString(subjectKeyIdentifier).getEncoded());
            }
            catch (IOException e)
            {
                throw Exceptions.illegalArgumentException("unable to convert subjectKeyIdentifier: " + e.getMessage(), e);
            }
        }

        return selector;
    }

    public X509CertSelector getCertSelector(X509CertificateHolderSelector holderSelector)
    {
        return doConversion(holderSelector.getIssuer(), holderSelector.getSerialNumber(), holderSelector.getSubjectKeyIdentifier());
    }
}
