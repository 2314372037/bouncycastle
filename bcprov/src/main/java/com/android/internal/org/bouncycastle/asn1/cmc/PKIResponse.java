package com.android.internal.org.bouncycastle.asn1.cmc;

import com.android.internal.org.bouncycastle.asn1.ASN1EncodableVector;
import com.android.internal.org.bouncycastle.asn1.ASN1Object;
import com.android.internal.org.bouncycastle.asn1.ASN1Primitive;
import com.android.internal.org.bouncycastle.asn1.ASN1Sequence;
import com.android.internal.org.bouncycastle.asn1.ASN1TaggedObject;
import com.android.internal.org.bouncycastle.asn1.DERSequence;

/**
 * <pre>
 *    --  This defines the response message in the protocol
 *  id-cct-PKIResponse OBJECT IDENTIFIER ::= { id-cct 3 }
 *
 * ResponseBody ::= PKIResponse
 *
 * PKIResponse ::= SEQUENCE {
 *     controlSequence   SEQUENCE SIZE(0..MAX) OF TaggedAttribute,
 *     cmsSequence       SEQUENCE SIZE(0..MAX) OF TaggedContentInfo,
 *     otherMsgSequence  SEQUENCE SIZE(0..MAX) OF OtherMsg
 * }
 * </pre>
 */
public class PKIResponse
    extends ASN1Object
{
    public static final TaggedContentInfo[] EMPTY_CMS_SEQUENCE = new TaggedContentInfo[0];
    public static final OtherMsg[] EMPTY_OTHER_MSG = new OtherMsg[0];

    private final ASN1Sequence controlSequence;
    private final ASN1Sequence cmsSequence;
    private final ASN1Sequence otherMsgSequence;

    private PKIResponse(ASN1Sequence seq)
    {
        if (seq.size() != 3)
        {
            throw new IllegalArgumentException("incorrect sequence size");
        }
        this.controlSequence = ASN1Sequence.getInstance(seq.getObjectAt(0));
        this.cmsSequence = ASN1Sequence.getInstance(seq.getObjectAt(1));
        this.otherMsgSequence = ASN1Sequence.getInstance(seq.getObjectAt(2));
    }

    public static PKIResponse getInstance(Object o)
    {
        if (o instanceof PKIResponse)
        {
            return (PKIResponse)o;
        }

        if (o != null)
        {
            return new PKIResponse(ASN1Sequence.getInstance(o));
        }

        return null;
    }

    public static PKIResponse getInstance(
        ASN1TaggedObject obj,
        boolean explicit)
    {
        return getInstance(ASN1Sequence.getInstance(obj, explicit));
    }

    public PKIResponse(TaggedAttribute controlSequence)
    {
        this.controlSequence = new DERSequence(controlSequence);
        this.cmsSequence = new DERSequence();
        this.otherMsgSequence = new DERSequence();
    }

    public PKIResponse(TaggedAttribute[] controlSequence, TaggedContentInfo[] cmsSequence, OtherMsg[] otherMsgSequence)
    {
        this.controlSequence = new DERSequence(controlSequence);
        this.cmsSequence = new DERSequence(cmsSequence);
        this.otherMsgSequence = new DERSequence(otherMsgSequence);
    }

    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector v = new ASN1EncodableVector(3);

        v.add(controlSequence);
        v.add(cmsSequence);
        v.add(otherMsgSequence);

        return new DERSequence(v);
    }

    public ASN1Sequence getControlSequence()
    {
        return controlSequence;
    }

    public ASN1Sequence getCmsSequence()
    {
        return cmsSequence;
    }

    public ASN1Sequence getOtherMsgSequence()
    {
        return otherMsgSequence;
    }
}
