package com.android.internal.org.bouncycastle.jce.interfaces;

import java.util.Enumeration;

import com.android.internal.org.bouncycastle.asn1.ASN1Encodable;
import com.android.internal.org.bouncycastle.asn1.ASN1ObjectIdentifier;

/**
 * allow us to set attributes on objects that can go into a PKCS12 store.
 */
public interface PKCS12BagAttributeCarrier
{
    void setBagAttribute(
        ASN1ObjectIdentifier oid,
        ASN1Encodable attribute);

    ASN1Encodable getBagAttribute(
        ASN1ObjectIdentifier oid);

    Enumeration getBagAttributeKeys();
}
