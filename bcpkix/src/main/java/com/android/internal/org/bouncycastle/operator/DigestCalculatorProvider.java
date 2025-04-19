package com.android.internal.org.bouncycastle.operator;

import com.android.internal.org.bouncycastle.asn1.x509.AlgorithmIdentifier;

/**
 * The base interface for a provider of DigestCalculator implementations.
 */
public interface DigestCalculatorProvider
{
    DigestCalculator get(AlgorithmIdentifier digestAlgorithmIdentifier)
        throws OperatorCreationException;
}
