package com.android.internal.org.bouncycastle.eac.operator;

import java.io.OutputStream;

import com.android.internal.org.bouncycastle.asn1.ASN1ObjectIdentifier;

public interface EACSigner
{
    ASN1ObjectIdentifier getUsageIdentifier();

    /**
     * Returns a stream that will accept data for the purpose of calculating
     * a signature. Use com.android.internal.org.bouncycastle.util.io.TeeOutputStream if you want to accumulate
     * the data on the fly as well.
     *
     * @return an OutputStream
     */
    OutputStream getOutputStream();

    /**
     * Returns a signature based on the current data written to the stream, since the
     * start or the last call to getSignature().
     *
     * @return bytes representing the signature.
     */
    byte[] getSignature();
}
