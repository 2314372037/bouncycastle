package com.android.internal.org.bouncycastle.cms.bc;

import java.io.InputStream;

import com.android.internal.org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import com.android.internal.org.bouncycastle.cms.CMSException;
import com.android.internal.org.bouncycastle.cms.RecipientOperator;
import com.android.internal.org.bouncycastle.crypto.BufferedBlockCipher;
import com.android.internal.org.bouncycastle.crypto.StreamCipher;
import com.android.internal.org.bouncycastle.crypto.params.KeyParameter;
import com.android.internal.org.bouncycastle.operator.InputDecryptor;
import com.android.internal.org.bouncycastle.operator.bc.BcSymmetricKeyUnwrapper;

public class BcKEKEnvelopedRecipient
    extends BcKEKRecipient
{
    public BcKEKEnvelopedRecipient(BcSymmetricKeyUnwrapper unwrapper)
    {
        super(unwrapper);
    }

    public RecipientOperator getRecipientOperator(AlgorithmIdentifier keyEncryptionAlgorithm, final AlgorithmIdentifier contentEncryptionAlgorithm, byte[] encryptedContentEncryptionKey)
        throws CMSException
    {
        KeyParameter secretKey = (KeyParameter)extractSecretKey(keyEncryptionAlgorithm, contentEncryptionAlgorithm, encryptedContentEncryptionKey);

        final Object dataCipher = EnvelopedDataHelper.createContentCipher(false, secretKey, contentEncryptionAlgorithm);

        return new RecipientOperator(new InputDecryptor()
        {
            public AlgorithmIdentifier getAlgorithmIdentifier()
            {
                return contentEncryptionAlgorithm;
            }

            public InputStream getInputStream(InputStream dataOut)
            {
                if (dataCipher instanceof BufferedBlockCipher)
                {
                    return new com.android.internal.org.bouncycastle.crypto.io.CipherInputStream(dataOut, (BufferedBlockCipher)dataCipher);
                }
                else
                {
                    return new com.android.internal.org.bouncycastle.crypto.io.CipherInputStream(dataOut, (StreamCipher)dataCipher);
                }
            }
        });
    }
}
