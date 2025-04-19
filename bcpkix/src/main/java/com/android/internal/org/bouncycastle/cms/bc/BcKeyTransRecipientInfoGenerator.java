package com.android.internal.org.bouncycastle.cms.bc;

import com.android.internal.org.bouncycastle.asn1.cms.IssuerAndSerialNumber;
import com.android.internal.org.bouncycastle.cert.X509CertificateHolder;
import com.android.internal.org.bouncycastle.cms.KeyTransRecipientInfoGenerator;
import com.android.internal.org.bouncycastle.operator.bc.BcAsymmetricKeyWrapper;

public abstract class BcKeyTransRecipientInfoGenerator
    extends KeyTransRecipientInfoGenerator
{
    public BcKeyTransRecipientInfoGenerator(X509CertificateHolder recipientCert, BcAsymmetricKeyWrapper wrapper)
    {
        super(new IssuerAndSerialNumber(recipientCert.toASN1Structure()), wrapper);
    }

    public BcKeyTransRecipientInfoGenerator(byte[] subjectKeyIdentifier, BcAsymmetricKeyWrapper wrapper)
    {
        super(subjectKeyIdentifier, wrapper);
    }
}