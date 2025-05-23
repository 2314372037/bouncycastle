package com.android.internal.org.bouncycastle.asn1.cmp;

import com.android.internal.org.bouncycastle.asn1.ASN1EncodableVector;
import com.android.internal.org.bouncycastle.asn1.ASN1Object;
import com.android.internal.org.bouncycastle.asn1.ASN1Primitive;
import com.android.internal.org.bouncycastle.asn1.ASN1Sequence;
import com.android.internal.org.bouncycastle.asn1.DERSequence;
import com.android.internal.org.bouncycastle.asn1.crmf.CertTemplate;
import com.android.internal.org.bouncycastle.asn1.x509.Extensions;
import com.android.internal.org.bouncycastle.asn1.x509.X509Extensions;

/**
 * <pre>
 * RevDetails ::= SEQUENCE {
 *          certDetails         CertTemplate,
 *          -- allows requester to specify as much as they can about
 *          -- the cert. for which revocation is requested
 *          -- (e.g., for cases in which serialNumber is not available)
 *          crlEntryDetails     Extensions       OPTIONAL
 *          -- requested crlEntryExtensions
 *      }
 * </pre>
 */
public class RevDetails
    extends ASN1Object
{
    private final CertTemplate certDetails;
    private Extensions crlEntryDetails;

    private RevDetails(ASN1Sequence seq)
    {
        certDetails = CertTemplate.getInstance(seq.getObjectAt(0));
        if (seq.size() > 1)
        {
            crlEntryDetails = Extensions.getInstance(seq.getObjectAt(1));
        }
    }

    public RevDetails(CertTemplate certDetails)
    {
        this.certDetails = certDetails;
    }

    /**
     * @param certDetails
     * @param crlEntryDetails
     * @deprecated use method taking Extensions
     */
    public RevDetails(CertTemplate certDetails, X509Extensions crlEntryDetails)
    {
        this.certDetails = certDetails;
        this.crlEntryDetails = Extensions.getInstance(crlEntryDetails.toASN1Primitive());
    }

    public RevDetails(CertTemplate certDetails, Extensions crlEntryDetails)
    {
        this.certDetails = certDetails;
        this.crlEntryDetails = crlEntryDetails;
    }

    public static RevDetails getInstance(Object o)
    {
        if (o instanceof RevDetails)
        {
            return (RevDetails)o;
        }

        if (o != null)
        {
            return new RevDetails(ASN1Sequence.getInstance(o));
        }

        return null;
    }

    public CertTemplate getCertDetails()
    {
        return certDetails;
    }

    public Extensions getCrlEntryDetails()
    {
        return crlEntryDetails;
    }


    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector v = new ASN1EncodableVector(2);

        v.add(certDetails);

        if (crlEntryDetails != null)
        {
            v.add(crlEntryDetails);
        }

        return new DERSequence(v);
    }
}
