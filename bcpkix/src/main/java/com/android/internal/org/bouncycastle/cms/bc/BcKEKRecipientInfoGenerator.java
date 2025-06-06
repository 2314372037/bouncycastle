package com.android.internal.org.bouncycastle.cms.bc;

import com.android.internal.org.bouncycastle.asn1.cms.KEKIdentifier;
import com.android.internal.org.bouncycastle.cms.KEKRecipientInfoGenerator;
import com.android.internal.org.bouncycastle.operator.bc.BcSymmetricKeyWrapper;

public class BcKEKRecipientInfoGenerator
    extends KEKRecipientInfoGenerator
{
    public BcKEKRecipientInfoGenerator(KEKIdentifier kekIdentifier, BcSymmetricKeyWrapper kekWrapper)
    {
        super(kekIdentifier, kekWrapper);
    }

    public BcKEKRecipientInfoGenerator(byte[] keyIdentifier, BcSymmetricKeyWrapper kekWrapper)
    {
        this(new KEKIdentifier(keyIdentifier, null, null), kekWrapper);
    }
}
