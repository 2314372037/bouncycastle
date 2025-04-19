package com.android.internal.org.bouncycastle.cms;

import com.android.internal.org.bouncycastle.asn1.ASN1Set;

interface AuthAttributesProvider
{
    ASN1Set getAuthAttributes();

    boolean isAead();
}
