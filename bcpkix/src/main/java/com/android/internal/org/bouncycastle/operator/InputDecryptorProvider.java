package com.android.internal.org.bouncycastle.operator;

import com.android.internal.org.bouncycastle.asn1.x509.AlgorithmIdentifier;

public interface InputDecryptorProvider
{
    public InputDecryptor get(AlgorithmIdentifier algorithm)
        throws OperatorCreationException;
}
