package com.android.internal.org.bouncycastle.asn1.eac;


import java.io.IOException;
import java.util.Enumeration;

import com.android.internal.org.bouncycastle.asn1.ASN1EncodableVector;
import com.android.internal.org.bouncycastle.asn1.ASN1InputStream;
import com.android.internal.org.bouncycastle.asn1.ASN1Object;
import com.android.internal.org.bouncycastle.asn1.ASN1ObjectIdentifier;
import com.android.internal.org.bouncycastle.asn1.ASN1OctetString;
import com.android.internal.org.bouncycastle.asn1.ASN1ParsingException;
import com.android.internal.org.bouncycastle.asn1.ASN1Primitive;
import com.android.internal.org.bouncycastle.asn1.ASN1Sequence;
import com.android.internal.org.bouncycastle.asn1.ASN1TaggedObject;
import com.android.internal.org.bouncycastle.asn1.BERTags;
import com.android.internal.org.bouncycastle.asn1.DERSequence;
import com.android.internal.org.bouncycastle.util.Arrays;


/**
 * an iso7816Certificate structure.
 * <pre>
 *  Certificate ::= SEQUENCE {
 *      CertificateBody         Iso7816CertificateBody,
 *      signature               DER Application specific
 *  }
 * </pre>
 */
public class CVCertificate
    extends ASN1Object
{
    private CertificateBody certificateBody;
    private byte[] signature;
    private int valid;
    private static int bodyValid = 0x01;
    private static int signValid = 0x02;

    /**
     * Sets the values of the certificate (body and signature).
     *
     * @param appSpe is a ASN1TaggedObject object containing body and signature.
     * @throws IOException if tags or value are incorrect.
     */
    private void setPrivateData(ASN1TaggedObject appSpe)
        throws IOException
    {
        valid = 0;
        if (appSpe.hasTag(BERTags.APPLICATION, EACTags.CARDHOLDER_CERTIFICATE))
        {
            ASN1Sequence content = ASN1Sequence.getInstance(appSpe.getBaseUniversal(false, BERTags.SEQUENCE));
            Enumeration en = content.getObjects();
            while (en.hasMoreElements())
            {
                Object obj = en.nextElement();
                if (obj instanceof ASN1TaggedObject)
                {
                    ASN1TaggedObject aSpe = ASN1TaggedObject.getInstance(obj, BERTags.APPLICATION);
                    switch (aSpe.getTagNo())
                    {
                    case EACTags.CERTIFICATE_CONTENT_TEMPLATE:
                        certificateBody = CertificateBody.getInstance(aSpe);
                        valid |= bodyValid;
                        break;
                    case EACTags.STATIC_INTERNAL_AUTHENTIFICATION_ONE_STEP:
                        signature = ASN1OctetString.getInstance(aSpe.getBaseUniversal(false, BERTags.OCTET_STRING)).getOctets();
                        valid |= signValid;
                        break;
                    default:
                        throw new IOException("Invalid tag, not an Iso7816CertificateStructure :" + aSpe.getTagNo());
                    }
                }
                else
                {
                    throw new IOException("Invalid Object, not an Iso7816CertificateStructure");
                }
            }
        }
        else
        {
            throw new IOException("not a CARDHOLDER_CERTIFICATE :" + appSpe.getTagNo());
        }

        if (valid != (signValid | bodyValid))
        {
            throw new IOException("invalid CARDHOLDER_CERTIFICATE :" + appSpe.getTagNo());
        }
    }

    /**
     * Create an iso7816Certificate structure from an ASN1InputStream.
     *
     * @param aIS the byte stream to parse.
     * @throws IOException if there is a problem parsing the data.
     */
    public CVCertificate(ASN1InputStream aIS)
        throws IOException
    {
        initFrom(aIS);
    }

    private void initFrom(ASN1InputStream aIS)
        throws IOException
    {
        ASN1Primitive obj;
        while ((obj = aIS.readObject()) != null)
        {
            if (obj instanceof ASN1TaggedObject)
            {
                setPrivateData((ASN1TaggedObject)obj);
            }
            else
            {
                throw new IOException("Invalid Input Stream for creating an Iso7816CertificateStructure");
            }
        }
    }

    /**
     * Create an iso7816Certificate structure from a ASN1TaggedObject.
     *
     * @param appSpe the ASN1TaggedObject object.
     * @return the Iso7816CertificateStructure represented by the ASN1TaggedObject object.
     * @throws IOException if there is a problem parsing the data.
     */
    private CVCertificate(ASN1TaggedObject appSpe)
        throws IOException
    {
        setPrivateData(appSpe);
    }

    /**
     * Create an iso7816Certificate structure from a body and its signature.
     *
     * @param body the Iso7816CertificateBody object containing the body.
     * @param signature   the byte array containing the signature
     * @throws IOException if there is a problem parsing the data.
     */
    public CVCertificate(CertificateBody body, byte[] signature)
        throws IOException
    {
        certificateBody = body;
        this.signature = Arrays.clone(signature);
        // patch remi
        valid |= bodyValid;
        valid |= signValid;
    }

    /**
     * Create an iso7816Certificate structure from an object.
     *
     * @param obj the Object to extract the certificate from.
     * @return the Iso7816CertificateStructure represented by the byte stream.
     */
    public static CVCertificate getInstance(Object obj)
    {
        if (obj instanceof CVCertificate)
        {
            return (CVCertificate)obj;
        }
        else if (obj != null)
        {
            try
            {
                return new CVCertificate(ASN1TaggedObject.getInstance(obj, BERTags.APPLICATION));
            }
            catch (IOException e)
            {
                throw new ASN1ParsingException("unable to parse data: " + e.getMessage(), e);
            }
        }

        return null;
    }

    /**
     * Gives the signature of the whole body. Type of signature is given in
     * the Iso7816CertificateBody.Iso7816PublicKey.ASN1ObjectIdentifier
     *
     * @return the signature of the body.
     */
    public byte[] getSignature()
    {
        return Arrays.clone(signature);
    }

    /**
     * Gives the body of the certificate.
     *
     * @return the body.
     */
    public CertificateBody getBody()
    {
        return certificateBody;
    }

    /**
     * @see com.android.internal.org.bouncycastle.asn1.ASN1Object#toASN1Primitive()
     */
    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector v = new ASN1EncodableVector(2);

        v.add(certificateBody);
        v.add(EACTagged.create(EACTags.STATIC_INTERNAL_AUTHENTIFICATION_ONE_STEP, signature));

        return EACTagged.create(EACTags.CARDHOLDER_CERTIFICATE, new DERSequence(v));
    }

    /**
     * @return the Holder authorization and role (CVCA, DV, IS).
     */
    public ASN1ObjectIdentifier getHolderAuthorization()
        throws IOException
    {
        CertificateHolderAuthorization cha = certificateBody.getCertificateHolderAuthorization();
        return cha.getOid();
    }

    /**
     * @return the date of the certificate generation
     */
    public PackedDate getEffectiveDate()
        throws IOException
    {
        return certificateBody.getCertificateEffectiveDate();
    }


    /**
     * @return the type of certificate (request or profile)
     *         value is either Iso7816CertificateBody.profileType
     *         or Iso7816CertificateBody.requestType. Any other value
     *         is not valid.
     */
    public int getCertificateType()
    {
        return this.certificateBody.getCertificateType();
    }

    /**
     * @return the date of the certificate generation
     */
    public PackedDate getExpirationDate()
        throws IOException
    {
        return certificateBody.getCertificateExpirationDate();
    }


    /**
     * return a bits field coded on one byte. For signification of the
     * several bit see Iso7816CertificateHolderAuthorization
     *
     * @return role and access rigth
     * @throws IOException
     * @see CertificateHolderAuthorization
     */
    public int getRole()
        throws IOException
    {
        CertificateHolderAuthorization cha = certificateBody.getCertificateHolderAuthorization();
        return cha.getAccessRights();
    }

    /**
     * @return the Authority Reference field of the certificate
     * @throws IOException
     */
    public CertificationAuthorityReference getAuthorityReference()
        throws IOException
    {
        return certificateBody.getCertificationAuthorityReference();
    }

    /**
     * @return the Holder Reference Field of the certificate
     * @throws IOException
     */
    public CertificateHolderReference getHolderReference()
        throws IOException
    {
        return certificateBody.getCertificateHolderReference();
    }

    /**
     * @return the bits corresponding to the role intented for the certificate
     *         See Iso7816CertificateHolderAuthorization static int for values
     * @throws IOException
     */
    public int getHolderAuthorizationRole()
        throws IOException
    {
        int rights = certificateBody.getCertificateHolderAuthorization().getAccessRights();
        return rights & 0xC0;
    }

    /**
     * @return the bits corresponding the authorizations contained in the certificate
     *         See Iso7816CertificateHolderAuthorization static int for values
     * @throws IOException
     */
    public Flags getHolderAuthorizationRights()
        throws IOException
    {
        return new Flags(certificateBody.getCertificateHolderAuthorization().getAccessRights() & 0x1F);
    }
}
