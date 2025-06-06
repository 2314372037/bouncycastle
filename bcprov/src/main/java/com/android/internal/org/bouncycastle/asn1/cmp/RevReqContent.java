package com.android.internal.org.bouncycastle.asn1.cmp;

import com.android.internal.org.bouncycastle.asn1.ASN1Object;
import com.android.internal.org.bouncycastle.asn1.ASN1Primitive;
import com.android.internal.org.bouncycastle.asn1.ASN1Sequence;
import com.android.internal.org.bouncycastle.asn1.DERSequence;

/**
 *  <pre>
 *       RevReqContent ::= SEQUENCE OF RevDetails
 *  </pre>
 */
public class RevReqContent
    extends ASN1Object
{
    private final ASN1Sequence content;

    private RevReqContent(ASN1Sequence seq)
    {
        content = seq;
    }

    public RevReqContent(RevDetails revDetails)
    {
        this.content = new DERSequence(revDetails);
    }

    public RevReqContent(RevDetails[] revDetailsArray)
    {
        this.content = new DERSequence(revDetailsArray);
    }

    public static RevReqContent getInstance(Object o)
    {
        if (o instanceof RevReqContent)
        {
            return (RevReqContent)o;
        }

        if (o != null)
        {
            return new RevReqContent(ASN1Sequence.getInstance(o));
        }

        return null;
    }

    public RevDetails[] toRevDetailsArray()
    {
        RevDetails[] result = new RevDetails[content.size()];

        for (int i = 0; i != result.length; i++)
        {
            result[i] = RevDetails.getInstance(content.getObjectAt(i));
        }

        return result;
    }

    /**
     * @return a basic ASN.1 object representation.
     */
    public ASN1Primitive toASN1Primitive()
    {
        return content;
    }
}
