package com.android.internal.org.bouncycastle.cms;

import com.android.internal.org.bouncycastle.asn1.x509.AlgorithmIdentifier;

public interface KeyTransRecipient
    extends Recipient
{
    RecipientOperator getRecipientOperator(AlgorithmIdentifier keyEncAlg, AlgorithmIdentifier contentEncryptionAlgorithm, byte[] encryptedContentKey)
        throws CMSException;
}
