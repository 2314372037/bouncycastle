package com.android.internal.org.bouncycastle.its;

import java.io.IOException;
import java.io.OutputStream;

import com.android.internal.org.bouncycastle.its.operator.ECDSAEncoder;
import com.android.internal.org.bouncycastle.its.operator.ITSContentVerifierProvider;
import com.android.internal.org.bouncycastle.oer.OEREncoder;
import com.android.internal.org.bouncycastle.oer.its.ieee1609dot2.CertificateBase;
import com.android.internal.org.bouncycastle.oer.its.ieee1609dot2.IssuerIdentifier;
import com.android.internal.org.bouncycastle.oer.its.ieee1609dot2.basetypes.PublicEncryptionKey;
import com.android.internal.org.bouncycastle.oer.its.ieee1609dot2.basetypes.Signature;
import com.android.internal.org.bouncycastle.oer.its.template.ieee1609dot2.IEEE1609dot2;
import com.android.internal.org.bouncycastle.operator.ContentVerifier;
import com.android.internal.org.bouncycastle.util.Encodable;

public class ITSCertificate
    implements Encodable
{
    private final CertificateBase certificate;

    public ITSCertificate(CertificateBase certificate)
    {
        this.certificate = certificate;
    }

    public IssuerIdentifier getIssuer()
    {
        return certificate.getIssuer();
    }

    public ITSValidityPeriod getValidityPeriod()
    {
        return new ITSValidityPeriod(certificate.getToBeSigned().getValidityPeriod());
    }

    /**
     * Return the certificate's public encryption key, if present.
     *
     * @return
     */
    public ITSPublicEncryptionKey getPublicEncryptionKey()
    {
        PublicEncryptionKey encryptionKey = certificate.getToBeSigned().getEncryptionKey();

        if (encryptionKey != null)
        {
            return new ITSPublicEncryptionKey(encryptionKey);
        }

        return null;
    }

    public boolean isSignatureValid(ITSContentVerifierProvider verifierProvider)
        throws Exception
    {
        ContentVerifier contentVerifier = verifierProvider.get(certificate.getSignature().getChoice());

        OutputStream verOut = contentVerifier.getOutputStream();


        verOut.write(
            OEREncoder.toByteArray(certificate.getToBeSigned(),
                IEEE1609dot2.ToBeSignedCertificate.build()));

        verOut.close();

        Signature sig = certificate.getSignature();

        return contentVerifier.verify(ECDSAEncoder.toX962(sig));
    }

    public CertificateBase toASN1Structure()
    {
        return certificate;
    }

    public byte[] getEncoded()
        throws IOException
    {
        return OEREncoder.toByteArray(certificate, IEEE1609dot2.CertificateBase.build());
    }
}
