package com.android.internal.org.bouncycastle.cms;

import com.android.internal.org.bouncycastle.asn1.cms.RecipientInfo;
import com.android.internal.org.bouncycastle.operator.GenericKey;

public interface RecipientInfoGenerator
{
    RecipientInfo generate(GenericKey contentEncryptionKey)
        throws CMSException;
}
