package com.android.internal.org.bouncycastle.oer.its.etsi102941;

import com.android.internal.org.bouncycastle.asn1.ASN1Boolean;
import com.android.internal.org.bouncycastle.asn1.ASN1Sequence;
import com.android.internal.org.bouncycastle.oer.its.etsi102941.basetypes.Version;
import com.android.internal.org.bouncycastle.oer.its.ieee1609dot2.basetypes.Time32;
import com.android.internal.org.bouncycastle.oer.its.ieee1609dot2.basetypes.UINT8;

public class FillCtl
    extends CtlFormat
{
    public FillCtl(Version version, Time32 nextUpdate, ASN1Boolean isFullCtl, UINT8 ctlSequence, SequenceOfCtlCommand ctlCommands)
    {
        super(version, nextUpdate, isFullCtl, ctlSequence, ctlCommands);
    }

    protected FillCtl(ASN1Sequence seq)
    {
        super(seq);
    }

    public static FillCtl getInstance(Object o)
    {
        if (o instanceof FillCtl)
        {
            return (FillCtl)o;
        }

        if (o != null)
        {
            return new FillCtl(ASN1Sequence.getInstance(o));
        }

        return null;
    }

}
