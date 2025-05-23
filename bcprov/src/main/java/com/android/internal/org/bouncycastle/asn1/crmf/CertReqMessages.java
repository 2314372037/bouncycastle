package com.android.internal.org.bouncycastle.asn1.crmf;

import com.android.internal.org.bouncycastle.asn1.ASN1EncodableVector;
import com.android.internal.org.bouncycastle.asn1.ASN1Object;
import com.android.internal.org.bouncycastle.asn1.ASN1Primitive;
import com.android.internal.org.bouncycastle.asn1.ASN1Sequence;
import com.android.internal.org.bouncycastle.asn1.DERSequence;

public class CertReqMessages
    extends ASN1Object
{
    private ASN1Sequence content;

    private CertReqMessages(ASN1Sequence seq)
    {
        content = seq;
    }

    public static CertReqMessages getInstance(Object o)
    {
        if (o instanceof CertReqMessages)
        {
            return (CertReqMessages)o;
        }

        if (o != null)
        {
            return new CertReqMessages(ASN1Sequence.getInstance(o));
        }

        return null;
    }

    public CertReqMessages(
        CertReqMsg msg)
    {
        content = new DERSequence(msg);
    }

    public CertReqMessages(
        CertReqMsg[] msgs)
    {
        content = new DERSequence(msgs);
    }

    public CertReqMsg[] toCertReqMsgArray()
    {
        CertReqMsg[] result = new CertReqMsg[content.size()];

        for (int i = 0; i != result.length; i++)
        {
            result[i] = CertReqMsg.getInstance(content.getObjectAt(i));
        }

        return result;
    }

    /**
     * <pre>
     * CertReqMessages ::= SEQUENCE SIZE (1..MAX) OF CertReqMsg
     * </pre>
     *
     * @return a basic ASN.1 object representation.
     */
    public ASN1Primitive toASN1Primitive()
    {
        return content;
    }
}
