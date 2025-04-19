package com.android.internal.org.bouncycastle.cms.bc;

import com.android.internal.org.bouncycastle.asn1.ASN1ObjectIdentifier;
import com.android.internal.org.bouncycastle.asn1.ASN1OctetString;
import com.android.internal.org.bouncycastle.asn1.pkcs.PBKDF2Params;
import com.android.internal.org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import com.android.internal.org.bouncycastle.cms.CMSException;
import com.android.internal.org.bouncycastle.cms.PasswordRecipient;
import com.android.internal.org.bouncycastle.cms.PasswordRecipientInfoGenerator;
import com.android.internal.org.bouncycastle.crypto.PBEParametersGenerator;
import com.android.internal.org.bouncycastle.crypto.Wrapper;
import com.android.internal.org.bouncycastle.crypto.generators.PKCS5S2ParametersGenerator;
import com.android.internal.org.bouncycastle.crypto.params.KeyParameter;
import com.android.internal.org.bouncycastle.crypto.params.ParametersWithIV;
import com.android.internal.org.bouncycastle.operator.GenericKey;

public class BcPasswordRecipientInfoGenerator
    extends PasswordRecipientInfoGenerator
{
    public BcPasswordRecipientInfoGenerator(ASN1ObjectIdentifier kekAlgorithm, char[] password)
    {
        super(kekAlgorithm, password);
    }

    protected byte[] calculateDerivedKey(int schemeID, AlgorithmIdentifier derivationAlgorithm, int keySize)
        throws CMSException
    {
        PBKDF2Params params = PBKDF2Params.getInstance(derivationAlgorithm.getParameters());
        byte[] encodedPassword = (schemeID == PasswordRecipient.PKCS5_SCHEME2) ? PBEParametersGenerator.PKCS5PasswordToBytes(password) : PBEParametersGenerator.PKCS5PasswordToUTF8Bytes(password);

        try
        {
            PKCS5S2ParametersGenerator gen = new PKCS5S2ParametersGenerator(EnvelopedDataHelper.getPRF(params.getPrf()));

            gen.init(encodedPassword, params.getSalt(), params.getIterationCount().intValue());

            return ((KeyParameter)gen.generateDerivedParameters(keySize)).getKey();
        }
        catch (Exception e)
        {
            throw new CMSException("exception creating derived key: " + e.getMessage(), e);
        }
    }

    public byte[] generateEncryptedBytes(AlgorithmIdentifier keyEncryptionAlgorithm, byte[] derivedKey, GenericKey contentEncryptionKey)
        throws CMSException
    {
        byte[] contentEncryptionKeySpec = ((KeyParameter)CMSUtils.getBcKey(contentEncryptionKey)).getKey();
        Wrapper keyEncryptionCipher = EnvelopedDataHelper.createRFC3211Wrapper(keyEncryptionAlgorithm.getAlgorithm());

        keyEncryptionCipher.init(true, new ParametersWithIV(new KeyParameter(derivedKey), ASN1OctetString.getInstance(keyEncryptionAlgorithm.getParameters()).getOctets()));

        return keyEncryptionCipher.wrap(contentEncryptionKeySpec, 0, contentEncryptionKeySpec.length);
    }
}
