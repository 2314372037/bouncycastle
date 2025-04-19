package com.android.internal.org.bouncycastle.cert.crmf.bc;

import java.io.OutputStream;
import java.security.SecureRandom;

import com.android.internal.org.bouncycastle.asn1.ASN1ObjectIdentifier;
import com.android.internal.org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import com.android.internal.org.bouncycastle.cert.crmf.CRMFException;
import com.android.internal.org.bouncycastle.crypto.CipherKeyGenerator;
import com.android.internal.org.bouncycastle.crypto.CryptoServicesRegistrar;
import com.android.internal.org.bouncycastle.crypto.params.KeyParameter;
import com.android.internal.org.bouncycastle.crypto.util.CipherFactory;
import com.android.internal.org.bouncycastle.operator.GenericKey;
import com.android.internal.org.bouncycastle.operator.OutputEncryptor;

/**
 * Lightweight CRMFOutputEncryptor builder.
 */
public class BcCRMFEncryptorBuilder
{
    private final ASN1ObjectIdentifier encryptionOID;
    private final int                  keySize;

    private CRMFHelper helper = new CRMFHelper();
    private SecureRandom random;

    public BcCRMFEncryptorBuilder(ASN1ObjectIdentifier encryptionOID)
    {
        this(encryptionOID, -1);
    }

    public BcCRMFEncryptorBuilder(ASN1ObjectIdentifier encryptionOID, int keySize)
    {
        this.encryptionOID = encryptionOID;
        this.keySize = keySize;
    }

    public BcCRMFEncryptorBuilder setSecureRandom(SecureRandom random)
    {
        this.random = random;

        return this;
    }

    public OutputEncryptor build()
        throws CRMFException
    {
        return new CRMFOutputEncryptor(encryptionOID, keySize, random);
    }

    private class CRMFOutputEncryptor
        implements OutputEncryptor
    {
        private KeyParameter encKey;
        private AlgorithmIdentifier algorithmIdentifier;
        private Object cipher;

        CRMFOutputEncryptor(ASN1ObjectIdentifier encryptionOID, int keySize, SecureRandom random)
            throws CRMFException
        {
            random = CryptoServicesRegistrar.getSecureRandom(random);

            CipherKeyGenerator keyGen = helper.createKeyGenerator(encryptionOID, random);

            encKey = new KeyParameter(keyGen.generateKey());
            algorithmIdentifier = helper.generateEncryptionAlgID(encryptionOID, encKey, random);
            cipher = helper.createContentCipher(true, encKey, algorithmIdentifier);
        }

        public AlgorithmIdentifier getAlgorithmIdentifier()
        {
            return algorithmIdentifier;
        }

        public OutputStream getOutputStream(OutputStream dOut)
        {
            return CipherFactory.createOutputStream(dOut, cipher);
        }

        public GenericKey getKey()
        {
            return new GenericKey(algorithmIdentifier, encKey.getKey());
        }
    }
}
