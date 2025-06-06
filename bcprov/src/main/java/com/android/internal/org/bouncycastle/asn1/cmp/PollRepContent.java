package com.android.internal.org.bouncycastle.asn1.cmp;

import com.android.internal.org.bouncycastle.asn1.ASN1EncodableVector;
import com.android.internal.org.bouncycastle.asn1.ASN1Integer;
import com.android.internal.org.bouncycastle.asn1.ASN1Object;
import com.android.internal.org.bouncycastle.asn1.ASN1Primitive;
import com.android.internal.org.bouncycastle.asn1.ASN1Sequence;
import com.android.internal.org.bouncycastle.asn1.DERSequence;

/**
 * PollRepContent ::= SEQUENCE OF SEQUENCE {
 * certReqId    INTEGER,
 * checkAfter   INTEGER,  -- time in seconds
 * reason       PKIFreeText OPTIONAL }
 */
public class PollRepContent
    extends ASN1Object
{
    private final ASN1Integer[] certReqId;
    private final ASN1Integer[] checkAfter;
    private final PKIFreeText[] reason;

    private PollRepContent(ASN1Sequence seq)
    {
        certReqId = new ASN1Integer[seq.size()];
        checkAfter = new ASN1Integer[seq.size()];
        reason = new PKIFreeText[seq.size()];

        for (int i = 0; i != seq.size(); i++)
        {
            ASN1Sequence s = ASN1Sequence.getInstance(seq.getObjectAt(i));

            certReqId[i] = ASN1Integer.getInstance(s.getObjectAt(0));
            checkAfter[i] = ASN1Integer.getInstance(s.getObjectAt(1));

            if (s.size() > 2)
            {
                reason[i] = PKIFreeText.getInstance(s.getObjectAt(2));
            }
        }
    }

    public PollRepContent(ASN1Integer certReqId, ASN1Integer checkAfter)
    {
        this(certReqId, checkAfter, null);
    }

    public PollRepContent(ASN1Integer certReqId, ASN1Integer checkAfter, PKIFreeText reason)
    {
        this.certReqId = new ASN1Integer[1];
        this.checkAfter = new ASN1Integer[1];
        this.reason = new PKIFreeText[1];

        this.certReqId[0] = certReqId;
        this.checkAfter[0] = checkAfter;
        this.reason[0] = reason;
    }

    public static PollRepContent getInstance(Object o)
    {
        if (o instanceof PollRepContent)
        {
            return (PollRepContent)o;
        }

        if (o != null)
        {
            return new PollRepContent(ASN1Sequence.getInstance(o));
        }

        return null;
    }

    public int size()
    {
        return certReqId.length;
    }

    public ASN1Integer getCertReqId(int index)
    {
        return certReqId[index];
    }

    public ASN1Integer getCheckAfter(int index)
    {
        return checkAfter[index];
    }

    public PKIFreeText getReason(int index)
    {
        return reason[index];
    }

    /**
     * <pre>
     * PollRepContent ::= SEQUENCE OF SEQUENCE {
     *         certReqId              INTEGER,
     *         checkAfter             INTEGER,  -- time in seconds
     *         reason                 PKIFreeText OPTIONAL
     *     }
     * </pre>
     *
     * @return a basic ASN.1 object representation.
     */
    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector outer = new ASN1EncodableVector(certReqId.length);

        for (int i = 0; i != certReqId.length; i++)
        {
            ASN1EncodableVector v = new ASN1EncodableVector(3);

            v.add(certReqId[i]);
            v.add(checkAfter[i]);

            if (reason[i] != null)
            {
                v.add(reason[i]);
            }

            outer.add(new DERSequence(v));
        }

        return new DERSequence(outer);
    }
}
