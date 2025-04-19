package com.android.internal.org.bouncycastle.cms.jcajce;

import com.android.internal.org.bouncycastle.asn1.x509.AlgorithmIdentifier;

interface KeyMaterialGenerator
{
    byte[] generateKDFMaterial(AlgorithmIdentifier keyAlgorithm, int keySize, byte[] userKeyMaterialParameters);
}
