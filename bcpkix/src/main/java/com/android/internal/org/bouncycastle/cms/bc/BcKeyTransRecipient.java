package com.android.internal.org.bouncycastle.cms.bc;

import com.android.internal.org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import com.android.internal.org.bouncycastle.cms.CMSException;
import com.android.internal.org.bouncycastle.cms.KeyTransRecipient;
import com.android.internal.org.bouncycastle.crypto.CipherParameters;
import com.android.internal.org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import com.android.internal.org.bouncycastle.operator.AsymmetricKeyUnwrapper;
import com.android.internal.org.bouncycastle.operator.OperatorException;
import com.android.internal.org.bouncycastle.operator.bc.BcRSAAsymmetricKeyUnwrapper;

public abstract class BcKeyTransRecipient
    implements KeyTransRecipient
{
    private AsymmetricKeyParameter recipientKey;

    public BcKeyTransRecipient(AsymmetricKeyParameter recipientKey)
    {
        this.recipientKey = recipientKey;
    }

    protected CipherParameters extractSecretKey(AlgorithmIdentifier keyEncryptionAlgorithm, AlgorithmIdentifier encryptedKeyAlgorithm, byte[] encryptedEncryptionKey)
        throws CMSException
    {
        AsymmetricKeyUnwrapper unwrapper = new BcRSAAsymmetricKeyUnwrapper(keyEncryptionAlgorithm, recipientKey);

        try
        {
            return CMSUtils.getBcKey(unwrapper.generateUnwrappedKey(encryptedKeyAlgorithm, encryptedEncryptionKey));
        }
        catch (OperatorException e)
        {
            throw new CMSException("exception unwrapping key: " + e.getMessage(), e);
        }
    }
}
