package com.android.internal.org.bouncycastle.operator;

import com.android.internal.org.bouncycastle.asn1.x509.AlgorithmIdentifier;

public interface InputExpanderProvider
{
    InputExpander get(AlgorithmIdentifier algorithm);
}
