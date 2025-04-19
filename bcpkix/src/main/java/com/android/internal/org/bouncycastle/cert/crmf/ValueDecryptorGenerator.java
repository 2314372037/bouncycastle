package com.android.internal.org.bouncycastle.cert.crmf;

import com.android.internal.org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import com.android.internal.org.bouncycastle.operator.InputDecryptor;

public interface ValueDecryptorGenerator
{
    InputDecryptor getValueDecryptor(AlgorithmIdentifier keyAlg, AlgorithmIdentifier symmAlg, byte[] encKey)
        throws CRMFException;
}
