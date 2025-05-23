package com.android.internal.org.bouncycastle.asn1.esf;

import com.android.internal.org.bouncycastle.asn1.ASN1IA5String;
import com.android.internal.org.bouncycastle.asn1.ASN1Primitive;

public class SPuri
{
    private ASN1IA5String uri;

    public static SPuri getInstance(
        Object obj)
    {
        if (obj instanceof SPuri)
        {
            return (SPuri) obj;
        }
        else if (obj instanceof ASN1IA5String)
        {
            return new SPuri(ASN1IA5String.getInstance(obj));
        }

        return null;
    }

    public SPuri(
        ASN1IA5String uri)
    {
        this.uri = uri;
    }

    public ASN1IA5String getUriIA5()
    {
        return uri;
    }

    /**
     * <pre>
     * SPuri ::= IA5String
     * </pre>
     */
    public ASN1Primitive toASN1Primitive()
    {
        return uri.toASN1Primitive();
    }
}
