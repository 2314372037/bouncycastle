package com.android.internal.org.bouncycastle.asn1.cmp;

import java.util.Enumeration;

import com.android.internal.org.bouncycastle.asn1.ASN1Encodable;
import com.android.internal.org.bouncycastle.asn1.ASN1EncodableVector;
import com.android.internal.org.bouncycastle.asn1.ASN1Object;
import com.android.internal.org.bouncycastle.asn1.ASN1Primitive;
import com.android.internal.org.bouncycastle.asn1.ASN1Sequence;
import com.android.internal.org.bouncycastle.asn1.ASN1TaggedObject;
import com.android.internal.org.bouncycastle.asn1.BERTags;
import com.android.internal.org.bouncycastle.asn1.DERSequence;
import com.android.internal.org.bouncycastle.asn1.DERTaggedObject;

/**
 * KeyRecRepContent ::= SEQUENCE {
 *          status                  PKIStatusInfo,
 *          newSigCert          [0] CMPCertificate OPTIONAL,
 *          caCerts             [1] SEQUENCE SIZE (1..MAX) OF
 *                                              CMPCertificate OPTIONAL,
 *          keyPairHist         [2] SEQUENCE SIZE (1..MAX) OF
 *                                              CertifiedKeyPair OPTIONAL
 *      }
 */
public class KeyRecRepContent
    extends ASN1Object
{
    private final PKIStatusInfo status;
    private CMPCertificate newSigCert;
    private ASN1Sequence caCerts;
    private ASN1Sequence keyPairHist;

    private KeyRecRepContent(ASN1Sequence seq)
    {
        Enumeration en = seq.getObjects();

        status = PKIStatusInfo.getInstance(en.nextElement());

        while (en.hasMoreElements())
        {
            ASN1TaggedObject tObj = ASN1TaggedObject.getInstance(en.nextElement(), BERTags.CONTEXT_SPECIFIC);

            switch (tObj.getTagNo())
            {
            case 0:
                newSigCert = CMPCertificate.getInstance(tObj.getExplicitBaseObject());
                break;
            case 1:
                caCerts = ASN1Sequence.getInstance(tObj.getExplicitBaseObject());
                break;
            case 2:
                keyPairHist = ASN1Sequence.getInstance(tObj.getExplicitBaseObject());
                break;
            default:
                throw new IllegalArgumentException("unknown tag number: " + tObj.getTagNo());
            }
        }
    }

    public static KeyRecRepContent getInstance(Object o)
    {
        if (o instanceof KeyRecRepContent)
        {
            return (KeyRecRepContent)o;
        }

        if (o != null)
        {
            return new KeyRecRepContent(ASN1Sequence.getInstance(o));
        }

        return null;
    }


    public PKIStatusInfo getStatus()
    {
        return status;
    }

    public CMPCertificate getNewSigCert()
    {
        return newSigCert;
    }

    public CMPCertificate[] getCaCerts()
    {
        if (caCerts == null)
        {
            return null;
        }

        CMPCertificate[] results = new CMPCertificate[caCerts.size()];

        for (int i = 0; i != results.length; i++)
        {
            results[i] = CMPCertificate.getInstance(caCerts.getObjectAt(i));
        }

        return results;
    }

    public CertifiedKeyPair[] getKeyPairHist()
    {
        if (keyPairHist == null)
        {
            return null;
        }

        CertifiedKeyPair[] results = new CertifiedKeyPair[keyPairHist.size()];

        for (int i = 0; i != results.length; i++)
        {
            results[i] = CertifiedKeyPair.getInstance(keyPairHist.getObjectAt(i));
        }

        return results;
    }

    /**
     * <pre>
     * KeyRecRepContent ::= SEQUENCE {
     *                         status                  PKIStatusInfo,
     *                         newSigCert          [0] CMPCertificate OPTIONAL,
     *                         caCerts             [1] SEQUENCE SIZE (1..MAX) OF
     *                                                           CMPCertificate OPTIONAL,
     *                         keyPairHist         [2] SEQUENCE SIZE (1..MAX) OF
     *                                                           CertifiedKeyPair OPTIONAL
     *              }
     * </pre>
     *
     * @return a basic ASN.1 object representation.
     */
    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector v = new ASN1EncodableVector(4);

        v.add(status);

        addOptional(v, 0, newSigCert);
        addOptional(v, 1, caCerts);
        addOptional(v, 2, keyPairHist);

        return new DERSequence(v);
    }

    private void addOptional(ASN1EncodableVector v, int tagNo, ASN1Encodable obj)
    {
        if (obj != null)
        {
            v.add(new DERTaggedObject(true, tagNo, obj));
        }
    }
}
