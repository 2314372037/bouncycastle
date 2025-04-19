package com.android.internal.org.bouncycastle.cms.jcajce;

import java.io.OutputStream;
import java.security.Key;

import javax.crypto.Mac;
import javax.crypto.SecretKey;

import com.android.internal.org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import com.android.internal.org.bouncycastle.cms.CMSException;
import com.android.internal.org.bouncycastle.cms.RecipientOperator;
import com.android.internal.org.bouncycastle.jcajce.io.MacOutputStream;
import com.android.internal.org.bouncycastle.operator.GenericKey;
import com.android.internal.org.bouncycastle.operator.MacCalculator;
import com.android.internal.org.bouncycastle.operator.jcajce.JceGenericKey;


/**
 * the KeyTransRecipientInformation class for a recipient who has been sent a secret
 * key encrypted using their public key that needs to be used to
 * extract the message.
 */
public class JceKEKAuthenticatedRecipient
    extends JceKEKRecipient
{
    public JceKEKAuthenticatedRecipient(SecretKey recipientKey)
    {
        super(recipientKey);
    }

    public RecipientOperator getRecipientOperator(AlgorithmIdentifier keyEncryptionAlgorithm, final AlgorithmIdentifier contentMacAlgorithm, byte[] encryptedContentEncryptionKey)
        throws CMSException
    {
        final Key secretKey = extractSecretKey(keyEncryptionAlgorithm, contentMacAlgorithm, encryptedContentEncryptionKey);

        final Mac dataMac = contentHelper.createContentMac(secretKey, contentMacAlgorithm);

        return new RecipientOperator(new MacCalculator()
        {
            public AlgorithmIdentifier getAlgorithmIdentifier()
            {
                return contentMacAlgorithm;
            }

            public GenericKey getKey()
            {
                return new JceGenericKey(contentMacAlgorithm, secretKey);
            }

            public OutputStream getOutputStream()
            {
                return new MacOutputStream(dataMac);
            }

            public byte[] getMac()
            {
                return dataMac.doFinal();
            }
        });
    }
}
