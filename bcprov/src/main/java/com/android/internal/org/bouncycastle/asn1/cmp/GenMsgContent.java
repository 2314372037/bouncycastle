package com.android.internal.org.bouncycastle.asn1.cmp;

import com.android.internal.org.bouncycastle.asn1.ASN1Object;
import com.android.internal.org.bouncycastle.asn1.ASN1Primitive;
import com.android.internal.org.bouncycastle.asn1.ASN1Sequence;
import com.android.internal.org.bouncycastle.asn1.DERSequence;

/**
 * <pre>GenMsgContent ::= SEQUENCE OF InfoTypeAndValue</pre>
 */
public class GenMsgContent
    extends ASN1Object
{
    private final ASN1Sequence content;

    private GenMsgContent(ASN1Sequence seq)
    {
        content = seq;
    }

    public GenMsgContent(InfoTypeAndValue itv)
    {
        content = new DERSequence(itv);
    }

    public GenMsgContent(InfoTypeAndValue[] itvs)
    {
        content = new DERSequence(itvs);
    }

    public static GenMsgContent getInstance(Object o)
    {
        if (o instanceof GenMsgContent)
        {
            return (GenMsgContent)o;
        }

        if (o != null)
        {
            return new GenMsgContent(ASN1Sequence.getInstance(o));
        }

        return null;
    }

    public InfoTypeAndValue[] toInfoTypeAndValueArray()
    {
        InfoTypeAndValue[] result = new InfoTypeAndValue[content.size()];

        for (int i = 0; i != result.length; i++)
        {
            result[i] = InfoTypeAndValue.getInstance(content.getObjectAt(i));
        }

        return result;
    }

    /**
     * <pre>
     * GenMsgContent ::= SEQUENCE OF InfoTypeAndValue
     * </pre>
     *
     * @return a basic ASN.1 object representation.
     */
    public ASN1Primitive toASN1Primitive()
    {
        return content;
    }
}
