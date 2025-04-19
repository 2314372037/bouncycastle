package com.android.internal.org.bouncycastle.oer.its.etsi102941;

import com.android.internal.org.bouncycastle.asn1.ASN1Sequence;
import com.android.internal.org.bouncycastle.oer.its.etsi103097.EtsiTs103097DataSigned;
import com.android.internal.org.bouncycastle.oer.its.ieee1609dot2.Ieee1609Dot2Content;

public class InnerEcRequestSignedForPop
    extends EtsiTs103097DataSigned
{
    public InnerEcRequestSignedForPop(Ieee1609Dot2Content content)
    {
        super(content);
    }

    protected InnerEcRequestSignedForPop(ASN1Sequence src)
    {
        super(src);
    }

    public static InnerEcRequestSignedForPop getInstance(Object o)
    {
        if (o instanceof InnerEcRequestSignedForPop)
        {
            return (InnerEcRequestSignedForPop)o;
        }
        if (o != null)
        {
            return new InnerEcRequestSignedForPop(ASN1Sequence.getInstance(o));
        }

        return null;
    }

}
