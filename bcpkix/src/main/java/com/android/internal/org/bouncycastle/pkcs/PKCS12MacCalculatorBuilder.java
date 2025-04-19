package com.android.internal.org.bouncycastle.pkcs;

import com.android.internal.org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import com.android.internal.org.bouncycastle.operator.MacCalculator;
import com.android.internal.org.bouncycastle.operator.OperatorCreationException;

public interface PKCS12MacCalculatorBuilder
{
    MacCalculator build(char[] password)
        throws OperatorCreationException;

    AlgorithmIdentifier getDigestAlgorithmIdentifier();
}
