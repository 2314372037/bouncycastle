package com.android.internal.org.bouncycastle.asn1.crmf;

import com.android.internal.org.bouncycastle.asn1.ASN1Choice;
import com.android.internal.org.bouncycastle.asn1.ASN1Encodable;
import com.android.internal.org.bouncycastle.asn1.ASN1Object;
import com.android.internal.org.bouncycastle.asn1.ASN1Primitive;
import com.android.internal.org.bouncycastle.asn1.ASN1TaggedObject;
import com.android.internal.org.bouncycastle.asn1.DERTaggedObject;
import com.android.internal.org.bouncycastle.asn1.cms.EnvelopedData;

/**
 * EncryptedKey ::= CHOICE {
 *          encryptedValue        EncryptedValue, -- deprecated
 *          envelopedData     [0] EnvelopedData }
 */
public class EncryptedKey
    extends ASN1Object
    implements ASN1Choice
{
    private EnvelopedData envelopedData;
    private EncryptedValue encryptedValue;

    public static EncryptedKey getInstance(Object o)
    {
        if (o instanceof EncryptedKey)
        {
            return (EncryptedKey)o;
        }
        else if (o instanceof ASN1TaggedObject)
        {
            return new EncryptedKey(EnvelopedData.getInstance((ASN1TaggedObject)o, false));
        }
        else
        {
            return new EncryptedKey(EncryptedValue.getInstance(o));
        }
    }

    public EncryptedKey(EnvelopedData envelopedData)
    {
        this.envelopedData = envelopedData;
    }

    public EncryptedKey(EncryptedValue encryptedValue)
    {
        this.encryptedValue = encryptedValue;
    }

    public boolean isEncryptedValue()
    {
        return encryptedValue != null;
    }

    public ASN1Encodable getValue()
    {
        if (encryptedValue != null)
        {
            return encryptedValue;
        }

        return envelopedData;
    }

    /**
     * <pre>
     *    EncryptedKey ::= CHOICE {
     *        encryptedValue        EncryptedValue, -- deprecated
     *        envelopedData     [0] EnvelopedData }
     *        -- The encrypted private key MUST be placed in the envelopedData
     *        -- encryptedContentInfo encryptedContent OCTET STRING.
     * </pre>
     */
    public ASN1Primitive toASN1Primitive()
    {
        if (encryptedValue != null)
        {
            return encryptedValue.toASN1Primitive();
        }

        return new DERTaggedObject(false, 0, envelopedData);
    }
}
