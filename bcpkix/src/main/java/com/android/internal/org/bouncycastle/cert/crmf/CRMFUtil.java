package com.android.internal.org.bouncycastle.cert.crmf;

import java.io.IOException;
import java.io.OutputStream;

import com.android.internal.org.bouncycastle.asn1.ASN1Encodable;
import com.android.internal.org.bouncycastle.asn1.ASN1Encoding;
import com.android.internal.org.bouncycastle.asn1.ASN1Object;
import com.android.internal.org.bouncycastle.asn1.ASN1ObjectIdentifier;
import com.android.internal.org.bouncycastle.asn1.x509.ExtensionsGenerator;
import com.android.internal.org.bouncycastle.cert.CertIOException;

class CRMFUtil
{
    static void derEncodeToStream(ASN1Object obj, OutputStream stream)
    {
        try
        {
            obj.encodeTo(stream, ASN1Encoding.DER);
            stream.close();
        }
        catch (IOException e)
        {
            throw new CRMFRuntimeException("unable to DER encode object: " + e.getMessage(), e);
        }
    }

    static void addExtension(ExtensionsGenerator extGenerator, ASN1ObjectIdentifier oid, boolean isCritical, ASN1Encodable value)
        throws CertIOException
    {
        try
        {
            extGenerator.addExtension(oid, isCritical, value);
        }
        catch (IOException e)
        {
            throw new CertIOException("cannot encode extension: " + e.getMessage(), e);
        }
    }
}
