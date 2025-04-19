package com.android.internal.org.bouncycastle.cert.path.validations;

import com.android.internal.org.bouncycastle.cert.X509CertificateHolder;

class ValidationUtils
{
    static boolean isSelfIssued(X509CertificateHolder cert)
    {
        return cert.getSubject().equals(cert.getIssuer());
    }
}
