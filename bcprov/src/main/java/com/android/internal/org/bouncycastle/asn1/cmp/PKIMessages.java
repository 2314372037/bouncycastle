package com.android.internal.org.bouncycastle.asn1.cmp;

import com.android.internal.org.bouncycastle.asn1.ASN1Object;
import com.android.internal.org.bouncycastle.asn1.ASN1Primitive;
import com.android.internal.org.bouncycastle.asn1.ASN1Sequence;
import com.android.internal.org.bouncycastle.asn1.DERSequence;

/**
 * PKIMessages ::= SEQUENCE SIZE (1..MAX) OF PKIMessage
 */
public class PKIMessages
    extends ASN1Object
{
    private final ASN1Sequence content;

    protected PKIMessages(ASN1Sequence seq)
    {
        content = seq;
    }

    public PKIMessages(PKIMessage msg)
    {
        content = new DERSequence(msg);
    }

    public PKIMessages(PKIMessage[] msgs)
    {
        content = new DERSequence(msgs);
    }

    public static PKIMessages getInstance(Object o)
    {
        if (o instanceof PKIMessages)
        {
            return (PKIMessages)o;
        }

        if (o != null)
        {
            return new PKIMessages(ASN1Sequence.getInstance(o));
        }

        return null;
    }

    public PKIMessage[] toPKIMessageArray()
    {
        PKIMessage[] result = new PKIMessage[content.size()];

        for (int i = 0; i != result.length; i++)
        {
            result[i] = PKIMessage.getInstance(content.getObjectAt(i));
        }

        return result;
    }

    /**
     * <pre>
     * PKIMessages ::= SEQUENCE SIZE (1..MAX) OF PKIMessage
     * </pre>
     *
     * @return a basic ASN.1 object representation.
     */
    public ASN1Primitive toASN1Primitive()
    {
        return content;
    }
}
