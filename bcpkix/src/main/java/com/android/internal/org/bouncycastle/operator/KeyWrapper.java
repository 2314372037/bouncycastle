package com.android.internal.org.bouncycastle.operator;

import com.android.internal.org.bouncycastle.asn1.x509.AlgorithmIdentifier;

public interface KeyWrapper
{
    AlgorithmIdentifier getAlgorithmIdentifier();

    byte[] generateWrappedKey(GenericKey encryptionKey)
        throws OperatorException;
}
