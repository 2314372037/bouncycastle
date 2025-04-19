package com.android.internal.org.bouncycastle.eac;

import java.io.OutputStream;

import com.android.internal.org.bouncycastle.asn1.ASN1Encoding;
import com.android.internal.org.bouncycastle.asn1.ASN1TaggedObject;
import com.android.internal.org.bouncycastle.asn1.BERTags;
import com.android.internal.org.bouncycastle.asn1.DEROctetString;
import com.android.internal.org.bouncycastle.asn1.DERTaggedObject;
import com.android.internal.org.bouncycastle.asn1.eac.CVCertificate;
import com.android.internal.org.bouncycastle.asn1.eac.CertificateBody;
import com.android.internal.org.bouncycastle.asn1.eac.CertificateHolderAuthorization;
import com.android.internal.org.bouncycastle.asn1.eac.CertificateHolderReference;
import com.android.internal.org.bouncycastle.asn1.eac.CertificationAuthorityReference;
import com.android.internal.org.bouncycastle.asn1.eac.EACTags;
import com.android.internal.org.bouncycastle.asn1.eac.PackedDate;
import com.android.internal.org.bouncycastle.asn1.eac.PublicKeyDataObject;
import com.android.internal.org.bouncycastle.eac.operator.EACSigner;

public class EACCertificateBuilder
{
    private static final byte [] ZeroArray = new byte [] {0};

    private PublicKeyDataObject publicKey;
    private CertificateHolderAuthorization certificateHolderAuthorization;
    private PackedDate certificateEffectiveDate;
    private PackedDate certificateExpirationDate;
    private CertificateHolderReference certificateHolderReference;
    private CertificationAuthorityReference certificationAuthorityReference;

    public EACCertificateBuilder(
        CertificationAuthorityReference certificationAuthorityReference,
        PublicKeyDataObject publicKey,
        CertificateHolderReference certificateHolderReference,
        CertificateHolderAuthorization certificateHolderAuthorization,
        PackedDate certificateEffectiveDate,
        PackedDate certificateExpirationDate)
    {
        this.certificationAuthorityReference = certificationAuthorityReference;
        this.publicKey = publicKey;
        this.certificateHolderReference = certificateHolderReference;
        this.certificateHolderAuthorization = certificateHolderAuthorization;
        this.certificateEffectiveDate = certificateEffectiveDate;
        this.certificateExpirationDate = certificateExpirationDate;
    }

    private CertificateBody buildBody()
    {
        ASN1TaggedObject certificateProfileIdentifier;

        certificateProfileIdentifier = new DERTaggedObject(false, BERTags.APPLICATION,
                EACTags.INTERCHANGE_PROFILE, new DEROctetString(ZeroArray));

        CertificateBody body = new CertificateBody(
                certificateProfileIdentifier,
                certificationAuthorityReference,
                publicKey,
                certificateHolderReference,
                certificateHolderAuthorization,
                certificateEffectiveDate,
                certificateExpirationDate);

        return body;
    }

    public EACCertificateHolder build(EACSigner signer)
        throws EACException
    {
        try
        {
            CertificateBody body = buildBody();

            OutputStream vOut = signer.getOutputStream();

            vOut.write(body.getEncoded(ASN1Encoding.DER));

            vOut.close();

            return new EACCertificateHolder(new CVCertificate(body, signer.getSignature()));
        }
        catch (Exception e)
        {
            throw new EACException("unable to process signature: " + e.getMessage(), e);
        }
    }
}
