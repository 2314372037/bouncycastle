package com.android.internal.org.bouncycastle.pkcs;

import com.android.internal.org.bouncycastle.asn1.x509.AlgorithmIdentifier;

public interface PKCS12MacCalculatorBuilderProvider
{
    PKCS12MacCalculatorBuilder get(AlgorithmIdentifier algorithmIdentifier);
}
