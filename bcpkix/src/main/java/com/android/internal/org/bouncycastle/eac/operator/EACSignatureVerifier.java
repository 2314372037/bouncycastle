package com.android.internal.org.bouncycastle.eac.operator;

import java.io.OutputStream;

import com.android.internal.org.bouncycastle.asn1.ASN1ObjectIdentifier;

public interface EACSignatureVerifier
{
    /**
     * Return the usage OID specifying the signature type.
     *
     * @return algorithm oid.
     */
    ASN1ObjectIdentifier getUsageIdentifier();

    /**
     * Returns a stream that will accept data for the purpose of calculating
     * a signature for later verification. Use com.android.internal.org.bouncycastle.util.io.TeeOutputStream if you want to accumulate
     * the data on the fly as well.
     *
     * @return an OutputStream
     */
    OutputStream getOutputStream();

    /**
     * @param expected expected value of the signature on the data.
     * @return true if the signature verifies, false otherwise
     */
    boolean verify(byte[] expected);
}