package com.android.internal.org.bouncycastle.internal.asn1.misc;

import com.android.internal.org.bouncycastle.asn1.ASN1EncodableVector;
import com.android.internal.org.bouncycastle.asn1.ASN1Object;
import com.android.internal.org.bouncycastle.asn1.ASN1OctetString;
import com.android.internal.org.bouncycastle.asn1.ASN1Primitive;
import com.android.internal.org.bouncycastle.asn1.ASN1Sequence;
import com.android.internal.org.bouncycastle.asn1.DEROctetString;
import com.android.internal.org.bouncycastle.asn1.DERSequence;
import com.android.internal.org.bouncycastle.util.Arrays;

public class IDEACBCPar
    extends ASN1Object
{
    ASN1OctetString  iv;

    public static IDEACBCPar getInstance(
        Object  o)
    {
        if (o instanceof IDEACBCPar)
        {
            return (IDEACBCPar)o;
        }
        else if (o != null)
        {
            return new IDEACBCPar(ASN1Sequence.getInstance(o));
        }

        return null;
    }

    public IDEACBCPar(
        byte[]  iv)
    {
        this.iv = new DEROctetString(Arrays.clone(iv));
    }

    private IDEACBCPar(
        ASN1Sequence  seq)
    {
        if (seq.size() == 1)
        {
            iv = (ASN1OctetString)seq.getObjectAt(0);
        }
        else
        {
            iv = null;
        }
    }

    public byte[] getIV()
    {
        if (iv != null)
        {
            return Arrays.clone(iv.getOctets());
        }
        else
        {
            return null;
        }
    }

    /**
     * Produce an object suitable for an ASN1OutputStream.
     * <pre>
     * IDEA-CBCPar ::= SEQUENCE {
     *                      iv    OCTET STRING OPTIONAL -- exactly 8 octets
     *                  }
     * </pre>
     */
    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector v = new ASN1EncodableVector(1);

        if (iv != null)
        {
            v.add(iv);
        }

        return new DERSequence(v);
    }
}
