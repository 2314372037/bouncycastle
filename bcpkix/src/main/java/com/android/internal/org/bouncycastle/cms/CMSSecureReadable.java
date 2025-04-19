package com.android.internal.org.bouncycastle.cms;

import java.io.IOException;
import java.io.InputStream;

import com.android.internal.org.bouncycastle.asn1.ASN1ObjectIdentifier;
import com.android.internal.org.bouncycastle.asn1.ASN1Set;

interface CMSSecureReadable
{
    ASN1ObjectIdentifier getContentType();

    InputStream getInputStream()
            throws IOException, CMSException;

    ASN1Set getAuthAttrSet();

    void setAuthAttrSet(ASN1Set set);

    boolean hasAdditionalData();
}
