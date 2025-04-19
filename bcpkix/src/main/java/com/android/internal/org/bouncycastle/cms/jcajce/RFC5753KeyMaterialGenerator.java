package com.android.internal.org.bouncycastle.cms.jcajce;

import java.io.IOException;

import com.android.internal.org.bouncycastle.asn1.ASN1Encoding;
import com.android.internal.org.bouncycastle.asn1.cms.ecc.ECCCMSSharedInfo;
import com.android.internal.org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import com.android.internal.org.bouncycastle.util.Pack;

class RFC5753KeyMaterialGenerator
    implements KeyMaterialGenerator
{
    public byte[] generateKDFMaterial(AlgorithmIdentifier keyAlgorithm, int keySize, byte[] userKeyMaterialParameters)
    {
        ECCCMSSharedInfo eccInfo = new ECCCMSSharedInfo(keyAlgorithm, userKeyMaterialParameters, Pack.intToBigEndian(keySize));

        try
        {
            return eccInfo.getEncoded(ASN1Encoding.DER);
        }
        catch (IOException e)
        {
            throw new IllegalStateException("Unable to create KDF material: " + e);
        }
    }
}
