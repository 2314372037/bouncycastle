package com.android.internal.org.bouncycastle.cert.path.validations;

import java.util.Collection;
import java.util.Iterator;

import com.android.internal.org.bouncycastle.asn1.x500.X500Name;
import com.android.internal.org.bouncycastle.cert.X509CRLHolder;
import com.android.internal.org.bouncycastle.cert.X509CertificateHolder;
import com.android.internal.org.bouncycastle.cert.path.CertPathValidation;
import com.android.internal.org.bouncycastle.cert.path.CertPathValidationContext;
import com.android.internal.org.bouncycastle.cert.path.CertPathValidationException;
import com.android.internal.org.bouncycastle.util.Memoable;
import com.android.internal.org.bouncycastle.util.Selector;
import com.android.internal.org.bouncycastle.util.Store;

public class CRLValidation
    implements CertPathValidation
{
    private Store crls;
    private X500Name workingIssuerName;

    public CRLValidation(X500Name trustAnchorName, Store crls)
    {
        this.workingIssuerName = trustAnchorName;
        this.crls = crls;
    }

    public void validate(CertPathValidationContext context, X509CertificateHolder certificate)
        throws CertPathValidationException
    {
        // TODO: add handling of delta CRLs
        Collection matches = crls.getMatches(new Selector()
        {
            public boolean match(Object obj)
            {
                X509CRLHolder crl = (X509CRLHolder)obj;

                return (crl.getIssuer().equals(workingIssuerName));
            }

            public Object clone()
            {
                return this;
            }
        });

        if (matches.isEmpty())
        {
            throw new CertPathValidationException("CRL for " + workingIssuerName + " not found");
        }

        for (Iterator it = matches.iterator(); it.hasNext();)
        {
            X509CRLHolder crl = (X509CRLHolder)it.next();

            // TODO: not quite right!
            if (crl.getRevokedCertificate(certificate.getSerialNumber()) != null)
            {
                throw new CertPathValidationException("Certificate revoked");
            }
        }

        this.workingIssuerName = certificate.getSubject();
    }

    public Memoable copy()
    {
        return new CRLValidation(workingIssuerName, crls);
    }

    public void reset(Memoable other)
    {
        CRLValidation v = (CRLValidation)other;

        this.workingIssuerName = v.workingIssuerName;
        this.crls = v.crls;
    }
}
