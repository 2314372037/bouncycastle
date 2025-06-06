package com.android.internal.org.bouncycastle.asn1.cmp;

import com.android.internal.org.bouncycastle.asn1.ASN1Choice;
import com.android.internal.org.bouncycastle.asn1.ASN1Object;
import com.android.internal.org.bouncycastle.asn1.ASN1Primitive;
import com.android.internal.org.bouncycastle.asn1.ASN1TaggedObject;
import com.android.internal.org.bouncycastle.asn1.ASN1Util;
import com.android.internal.org.bouncycastle.asn1.DERTaggedObject;
import com.android.internal.org.bouncycastle.asn1.x509.DistributionPointName;
import com.android.internal.org.bouncycastle.asn1.x509.GeneralNames;

/**
 * GenMsg:    {id-it TBD1}, SEQUENCE SIZE (1..MAX) OF CRLStatus
 * GenRep:    {id-it TBD2}, SEQUENCE SIZE (1..MAX) OF
 * CertificateList  |  &lt; absent &gt;
 * <p>
 * CRLSource ::= CHOICE {
 * dpn          [0] DistributionPointName,
 * issuer       [1] GeneralNames }
 * <p>
 */
public class CRLSource
    extends ASN1Object
    implements ASN1Choice
{

    private final DistributionPointName dpn;
    private final GeneralNames issuer;

    private CRLSource(ASN1TaggedObject ato)
    {
        if (ato.hasContextTag(0))
        {
            dpn = DistributionPointName.getInstance(ato, true);
            issuer = null;
        }
        else if (ato.hasContextTag(1))
        {
            dpn = null;
            issuer = GeneralNames.getInstance(ato, true);
        }
        else
        {
            throw new IllegalArgumentException("unknown tag " + ASN1Util.getTagText(ato));
        }
    }

    public CRLSource(DistributionPointName dpn, GeneralNames issuer)
    {
        if ((dpn == null) == (issuer == null))
        {
            throw new IllegalArgumentException("either dpn or issuer must be set");
        }
        this.dpn = dpn;
        this.issuer = issuer;
    }

    public static CRLSource getInstance(Object o)
    {
        if (o instanceof CRLSource)
        {
            return (CRLSource)o;
        }

        if (o != null)
        {
            return new CRLSource(ASN1TaggedObject.getInstance(o));
        }

        return null;
    }

    public DistributionPointName getDpn()
    {
        return dpn;
    }

    public GeneralNames getIssuer()
    {
        return issuer;
    }

    public ASN1Primitive toASN1Primitive()
    {
        if (dpn != null)
        {
            return new DERTaggedObject(true, 0, dpn);
        }

        return new DERTaggedObject(true, 1, issuer);
    }
}
