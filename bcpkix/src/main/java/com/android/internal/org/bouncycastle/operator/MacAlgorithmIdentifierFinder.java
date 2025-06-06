package com.android.internal.org.bouncycastle.operator;

import com.android.internal.org.bouncycastle.asn1.x509.AlgorithmIdentifier;

public interface MacAlgorithmIdentifierFinder
{
    /**
     * Find the algorithm identifier that matches with
     * the passed in digest name.
     *
     * @param macAlgName the name of the digest algorithm of interest.
     * @return an algorithm identifier for the MAC.
     */
    AlgorithmIdentifier find(String macAlgName);
}