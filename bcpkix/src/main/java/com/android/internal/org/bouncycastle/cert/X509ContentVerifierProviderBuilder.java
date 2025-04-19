package com.android.internal.org.bouncycastle.cert;

import com.android.internal.org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import com.android.internal.org.bouncycastle.operator.ContentVerifierProvider;
import com.android.internal.org.bouncycastle.operator.OperatorCreationException;

public interface X509ContentVerifierProviderBuilder
{
    ContentVerifierProvider build(SubjectPublicKeyInfo validatingKeyInfo)
        throws OperatorCreationException;

    ContentVerifierProvider build(X509CertificateHolder validatingKeyInfo)
        throws OperatorCreationException;
}
