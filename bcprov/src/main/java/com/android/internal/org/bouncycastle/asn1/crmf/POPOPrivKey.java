package com.android.internal.org.bouncycastle.asn1.crmf;

import com.android.internal.org.bouncycastle.asn1.ASN1BitString;
import com.android.internal.org.bouncycastle.asn1.ASN1Choice;
import com.android.internal.org.bouncycastle.asn1.ASN1Encodable;
import com.android.internal.org.bouncycastle.asn1.ASN1Integer;
import com.android.internal.org.bouncycastle.asn1.ASN1Object;
import com.android.internal.org.bouncycastle.asn1.ASN1Primitive;
import com.android.internal.org.bouncycastle.asn1.ASN1TaggedObject;
import com.android.internal.org.bouncycastle.asn1.DERTaggedObject;
import com.android.internal.org.bouncycastle.asn1.cms.EnvelopedData;

public class POPOPrivKey
    extends ASN1Object
    implements ASN1Choice
{
    public static final int thisMessage = 0;
    public static final int subsequentMessage = 1;
    public static final int dhMAC = 2;
    public static final int agreeMAC = 3;
    public static final int encryptedKey = 4;

    private int tagNo;
    private ASN1Encodable obj;

    private POPOPrivKey(ASN1TaggedObject obj)
    {
        this.tagNo = obj.getTagNo();

        switch (tagNo)
        {
        case thisMessage:
            this.obj = ASN1BitString.getInstance(obj, false);
            break;
        case subsequentMessage:
            this.obj = SubsequentMessage.valueOf(ASN1Integer.getInstance(obj, false).intValueExact());
            break;
        case dhMAC:
            this.obj = ASN1BitString.getInstance(obj, false);
            break;
        case agreeMAC:
            this.obj = PKMACValue.getInstance(obj, false);
            break;
        case encryptedKey:
            this.obj = EnvelopedData.getInstance(obj, false);
            break;
        default:
            throw new IllegalArgumentException("unknown tag in POPOPrivKey");
        }
    }

    public static POPOPrivKey getInstance(Object obj)
    {
        if (obj instanceof POPOPrivKey)
        {
            return (POPOPrivKey)obj;
        }
        if (obj != null)
        {
            return new POPOPrivKey(ASN1TaggedObject.getInstance(obj));
        }

        return null;
    }

    public static POPOPrivKey getInstance(ASN1TaggedObject obj, boolean explicit)
    {
        return getInstance(ASN1TaggedObject.getInstance(obj, true));
    }

    public POPOPrivKey(PKMACValue agreeMac)
    {
        this.tagNo = agreeMAC;
        this.obj = agreeMac;
    }

    public POPOPrivKey(SubsequentMessage msg)
    {
        this.tagNo = subsequentMessage;
        this.obj = msg;
    }

    public int getType()
    {
        return tagNo;
    }

    public ASN1Encodable getValue()
    {
        return obj;
    }

    /**
     * <pre>
     * POPOPrivKey ::= CHOICE {
     *        thisMessage       [0] BIT STRING,         -- Deprecated
     *         -- possession is proven in this message (which contains the private
     *         -- key itself (encrypted for the CA))
     *        subsequentMessage [1] SubsequentMessage,
     *         -- possession will be proven in a subsequent message
     *        dhMAC             [2] BIT STRING,         -- Deprecated
     *        agreeMAC          [3] PKMACValue,
     *        encryptedKey      [4] EnvelopedData }
     * </pre>
     */
    public ASN1Primitive toASN1Primitive()
    {
        return new DERTaggedObject(false, tagNo, obj);
    }
}
