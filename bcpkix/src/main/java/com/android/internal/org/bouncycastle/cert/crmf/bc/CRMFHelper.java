package com.android.internal.org.bouncycastle.cert.crmf.bc;

import java.security.SecureRandom;

import com.android.internal.org.bouncycastle.asn1.ASN1ObjectIdentifier;
import com.android.internal.org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import com.android.internal.org.bouncycastle.cert.crmf.CRMFException;
import com.android.internal.org.bouncycastle.crypto.CipherKeyGenerator;
import com.android.internal.org.bouncycastle.crypto.CipherParameters;
import com.android.internal.org.bouncycastle.crypto.params.KeyParameter;
import com.android.internal.org.bouncycastle.crypto.util.AlgorithmIdentifierFactory;
import com.android.internal.org.bouncycastle.crypto.util.CipherFactory;
import com.android.internal.org.bouncycastle.crypto.util.CipherKeyGeneratorFactory;

class CRMFHelper
{
    CRMFHelper()
    {
    }

    CipherKeyGenerator createKeyGenerator(ASN1ObjectIdentifier algorithm, SecureRandom random)
        throws CRMFException
    {
        try
        {
            return CipherKeyGeneratorFactory.createKeyGenerator(algorithm, random);
        }
        catch (IllegalArgumentException e)
        {
            throw new CRMFException(e.getMessage(), e);
        }
    }

    static Object createContentCipher(boolean forEncryption, CipherParameters encKey, AlgorithmIdentifier encryptionAlgID)
        throws CRMFException
    {
        try
        {
            return CipherFactory.createContentCipher(forEncryption, encKey, encryptionAlgID);
        }
        catch (IllegalArgumentException e)
        {
            throw new CRMFException(e.getMessage(), e);
        }
    }

    AlgorithmIdentifier generateEncryptionAlgID(ASN1ObjectIdentifier encryptionOID, KeyParameter encKey, SecureRandom random)
        throws CRMFException
    {
        try
        {
            return AlgorithmIdentifierFactory.generateEncryptionAlgID(encryptionOID, encKey.getKey().length * 8, random);
        }
        catch (IllegalArgumentException e)
        {
            throw new CRMFException(e.getMessage(), e);
        }
    }
}
