package com.android.internal.org.bouncycastle.asn1.cmp;

import java.math.BigInteger;

import com.android.internal.org.bouncycastle.asn1.ASN1Integer;
import com.android.internal.org.bouncycastle.asn1.ASN1Object;
import com.android.internal.org.bouncycastle.asn1.ASN1Primitive;
import com.android.internal.org.bouncycastle.asn1.ASN1Sequence;
import com.android.internal.org.bouncycastle.asn1.DERSequence;

/**
 * PollReqContent ::= SEQUENCE OF SEQUENCE {
 * certReqId    INTEGER }
 */
public class PollReqContent
    extends ASN1Object
{
    private final ASN1Sequence content;

    private PollReqContent(ASN1Sequence seq)
    {
        content = seq;
    }

    /**
     * Create a pollReqContent for a single certReqId.
     *
     * @param certReqId the certificate request ID.
     */
    public PollReqContent(ASN1Integer certReqId)
    {
        this(new DERSequence(new DERSequence(certReqId)));
    }

    /**
     * Create a pollReqContent for a multiple certReqIds.
     *
     * @param certReqIds the certificate request IDs.
     */
    public PollReqContent(ASN1Integer[] certReqIds)
    {
        this(new DERSequence(intsToSequence(certReqIds)));
    }

    /**
     * Create a pollReqContent for a single certReqId.
     *
     * @param certReqId the certificate request ID.
     */
    public PollReqContent(BigInteger certReqId)
    {
        this(new ASN1Integer(certReqId));
    }

    /**
     * Create a pollReqContent for a multiple certReqIds.
     *
     * @param certReqIds the certificate request IDs.
     */
    public PollReqContent(BigInteger[] certReqIds)
    {
        this(intsToASN1(certReqIds));
    }

    public static PollReqContent getInstance(Object o)
    {
        if (o instanceof PollReqContent)
        {
            return (PollReqContent)o;
        }

        if (o != null)
        {
            return new PollReqContent(ASN1Sequence.getInstance(o));
        }

        return null;
    }

    private static ASN1Integer[] sequenceToASN1IntegerArray(ASN1Sequence seq)
    {
        ASN1Integer[] result = new ASN1Integer[seq.size()];

        for (int i = 0; i != result.length; i++)
        {
            result[i] = ASN1Integer.getInstance(seq.getObjectAt(i));
        }

        return result;
    }

    private static DERSequence[] intsToSequence(ASN1Integer[] ids)
    {
        DERSequence[] result = new DERSequence[ids.length];

        for (int i = 0; i != result.length; i++)
        {
            result[i] = new DERSequence(ids[i]);
        }

        return result;
    }

    private static ASN1Integer[] intsToASN1(BigInteger[] ids)
    {
        ASN1Integer[] result = new ASN1Integer[ids.length];

        for (int i = 0; i != result.length; i++)
        {
            result[i] = new ASN1Integer(ids[i]);
        }

        return result;
    }

    public ASN1Integer[][] getCertReqIds()
    {
        ASN1Integer[][] result = new ASN1Integer[content.size()][];

        for (int i = 0; i != result.length; i++)
        {
            result[i] = sequenceToASN1IntegerArray((ASN1Sequence)content.getObjectAt(i));
        }

        return result;
    }

    public BigInteger[] getCertReqIdValues()
    {
        BigInteger[] result = new BigInteger[content.size()];

        for (int i = 0; i != result.length; i++)
        {
            result[i] = ASN1Integer.getInstance(
                ASN1Sequence.getInstance(content.getObjectAt(i)).getObjectAt(0)).getValue();
        }

        return result;
    }

    /**
     * <pre>
     * PollReqContent ::= SEQUENCE OF SEQUENCE {
     *                        certReqId              INTEGER
     * }
     * </pre>
     *
     * @return a basic ASN.1 object representation.
     */
    public ASN1Primitive toASN1Primitive()
    {
        return content;
    }
}
