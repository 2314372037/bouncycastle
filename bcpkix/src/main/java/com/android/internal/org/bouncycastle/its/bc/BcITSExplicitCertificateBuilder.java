package com.android.internal.org.bouncycastle.its.bc;

import com.android.internal.org.bouncycastle.crypto.params.ECPublicKeyParameters;
import com.android.internal.org.bouncycastle.its.ITSCertificate;
import com.android.internal.org.bouncycastle.its.ITSExplicitCertificateBuilder;
import com.android.internal.org.bouncycastle.its.ITSPublicEncryptionKey;
import com.android.internal.org.bouncycastle.its.operator.ITSContentSigner;
import com.android.internal.org.bouncycastle.oer.its.ieee1609dot2.CertificateId;
import com.android.internal.org.bouncycastle.oer.its.ieee1609dot2.ToBeSignedCertificate;

public class BcITSExplicitCertificateBuilder
    extends ITSExplicitCertificateBuilder
{
    /**
     * Base constructor for an ITS certificate.
     *
     * @param signer         the content signer to be used to generate the signature validating the certificate.
     * @param tbsCertificate
     */
    public BcITSExplicitCertificateBuilder(ITSContentSigner signer, ToBeSignedCertificate.Builder tbsCertificate)
    {
        super(signer, tbsCertificate);
    }

    public ITSCertificate build(
        CertificateId certificateId,
        ECPublicKeyParameters verificationKey)
    {

        return build(certificateId, verificationKey, null);
    }

    public ITSCertificate build(
        CertificateId certificateId,
        ECPublicKeyParameters verificationKey,
        ECPublicKeyParameters encryptionKey)
    {
        ITSPublicEncryptionKey publicEncryptionKey = null;
        if (encryptionKey != null)
        {
            publicEncryptionKey = new BcITSPublicEncryptionKey(encryptionKey);
        }

        return super.build(certificateId, new BcITSPublicVerificationKey(verificationKey), publicEncryptionKey);
    }
}
