package com.android.internal.org.bouncycastle.dvcs;

import com.android.internal.org.bouncycastle.asn1.ASN1Encodable;
import com.android.internal.org.bouncycastle.asn1.ASN1ObjectIdentifier;
import com.android.internal.org.bouncycastle.asn1.cms.ContentInfo;

public abstract class DVCSMessage
{
    private final ContentInfo contentInfo;

    protected DVCSMessage(ContentInfo contentInfo)
    {
        this.contentInfo = contentInfo;
    }

    public ASN1ObjectIdentifier getContentType()
    {
        return contentInfo.getContentType();
    }

    public abstract ASN1Encodable getContent();
}
