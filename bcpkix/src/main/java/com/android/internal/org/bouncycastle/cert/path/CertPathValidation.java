package com.android.internal.org.bouncycastle.cert.path;

import com.android.internal.org.bouncycastle.cert.X509CertificateHolder;
import com.android.internal.org.bouncycastle.util.Memoable;

public interface CertPathValidation
    extends Memoable
{
    public void validate(CertPathValidationContext context, X509CertificateHolder certificate)
        throws CertPathValidationException;
}
