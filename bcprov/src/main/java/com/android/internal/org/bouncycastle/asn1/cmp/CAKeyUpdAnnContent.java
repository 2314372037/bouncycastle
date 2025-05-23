package com.android.internal.org.bouncycastle.asn1.cmp;

import com.android.internal.org.bouncycastle.asn1.ASN1EncodableVector;
import com.android.internal.org.bouncycastle.asn1.ASN1Object;
import com.android.internal.org.bouncycastle.asn1.ASN1Primitive;
import com.android.internal.org.bouncycastle.asn1.ASN1Sequence;
import com.android.internal.org.bouncycastle.asn1.DERSequence;

/**
 * CAKeyUpdAnnContent ::= SEQUENCE {
 *          oldWithNew   CMPCertificate, -- old pub signed with new priv
 *          newWithOld   CMPCertificate, -- new pub signed with old priv
 *          newWithNew   CMPCertificate  -- new pub signed with new priv
 *      }
 */
public class CAKeyUpdAnnContent
    extends ASN1Object
{
    private final CMPCertificate oldWithNew;
    private final CMPCertificate newWithOld;
    private final CMPCertificate newWithNew;

    private CAKeyUpdAnnContent(ASN1Sequence seq)
    {
        oldWithNew = CMPCertificate.getInstance(seq.getObjectAt(0));
        newWithOld = CMPCertificate.getInstance(seq.getObjectAt(1));
        newWithNew = CMPCertificate.getInstance(seq.getObjectAt(2));
    }

    public CAKeyUpdAnnContent(CMPCertificate oldWithNew, CMPCertificate newWithOld, CMPCertificate newWithNew)
    {
        this.oldWithNew = oldWithNew;
        this.newWithOld = newWithOld;
        this.newWithNew = newWithNew;
    }

    public static CAKeyUpdAnnContent getInstance(Object o)
    {
        if (o instanceof CAKeyUpdAnnContent)
        {
            return (CAKeyUpdAnnContent)o;
        }

        if (o != null)
        {
            return new CAKeyUpdAnnContent(ASN1Sequence.getInstance(o));
        }

        return null;
    }

    public CMPCertificate getOldWithNew()
    {
        return oldWithNew;
    }

    public CMPCertificate getNewWithOld()
    {
        return newWithOld;
    }

    public CMPCertificate getNewWithNew()
    {
        return newWithNew;
    }

    /**
     * <pre>
     * CAKeyUpdAnnContent ::= SEQUENCE {
     *                             oldWithNew   CMPCertificate, -- old pub signed with new priv
     *                             newWithOld   CMPCertificate, -- new pub signed with old priv
     *                             newWithNew   CMPCertificate  -- new pub signed with new priv
     *  }
     * </pre>
     *
     * @return a basic ASN.1 object representation.
     */
    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector v = new ASN1EncodableVector(3);

        v.add(oldWithNew);
        v.add(newWithOld);
        v.add(newWithNew);

        return new DERSequence(v);
    }
}
