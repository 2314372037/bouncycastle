package com.android.internal.org.bouncycastle.asn1.x509;

import com.android.internal.org.bouncycastle.asn1.ASN1Object;
import com.android.internal.org.bouncycastle.asn1.ASN1OctetString;
import com.android.internal.org.bouncycastle.asn1.ASN1Primitive;
import com.android.internal.org.bouncycastle.asn1.ASN1TaggedObject;
import com.android.internal.org.bouncycastle.asn1.DEROctetString;
import com.android.internal.org.bouncycastle.util.Arrays;

/**
 * The SubjectKeyIdentifier object.
 * <pre>
 * SubjectKeyIdentifier::= OCTET STRING
 * </pre>
 */
public class SubjectKeyIdentifier
    extends ASN1Object
{
    private byte[] keyidentifier;

    public static SubjectKeyIdentifier getInstance(
        ASN1TaggedObject obj,
        boolean          explicit)
    {
        return getInstance(ASN1OctetString.getInstance(obj, explicit));
    }

    public static SubjectKeyIdentifier getInstance(
        Object obj)
    {
        if (obj instanceof SubjectKeyIdentifier)
        {
            return (SubjectKeyIdentifier)obj;
        }
        else if (obj != null)
        {
            return new SubjectKeyIdentifier(ASN1OctetString.getInstance(obj));
        }

        return null;
    }

    public static SubjectKeyIdentifier fromExtensions(Extensions extensions)
    {
        return getInstance(Extensions.getExtensionParsedValue(extensions, Extension.subjectKeyIdentifier));
    }

    public SubjectKeyIdentifier(
        byte[] keyid)
    {
        this.keyidentifier = Arrays.clone(keyid);
    }

    protected SubjectKeyIdentifier(
        ASN1OctetString keyid)
    {
        this(keyid.getOctets());
    }

    public byte[] getKeyIdentifier()
    {
        return Arrays.clone(keyidentifier);
    }

    public ASN1Primitive toASN1Primitive()
    {
        return new DEROctetString(getKeyIdentifier());
    }
}
