package com.android.internal.org.bouncycastle.asn1.pkcs;

import com.android.internal.org.bouncycastle.asn1.ASN1Encodable;
import com.android.internal.org.bouncycastle.asn1.ASN1Object;
import com.android.internal.org.bouncycastle.asn1.ASN1ObjectIdentifier;
import com.android.internal.org.bouncycastle.asn1.ASN1Primitive;
import com.android.internal.org.bouncycastle.asn1.ASN1Sequence;
import com.android.internal.org.bouncycastle.asn1.x509.AlgorithmIdentifier;

public class EncryptionScheme
    extends ASN1Object
{
    private AlgorithmIdentifier algId;

    public EncryptionScheme(
        ASN1ObjectIdentifier objectId)
    {
        this.algId = new AlgorithmIdentifier(objectId);
    }

    public EncryptionScheme(
        ASN1ObjectIdentifier objectId,
        ASN1Encodable parameters)
    {
        this.algId = new AlgorithmIdentifier(objectId, parameters);
    }

    private EncryptionScheme(
        ASN1Sequence  seq)
    {   
        this.algId = AlgorithmIdentifier.getInstance(seq);
    }

    public static EncryptionScheme getInstance(Object obj)
    {
        if (obj instanceof EncryptionScheme)
        {
            return (EncryptionScheme)obj;
        }
        else if (obj != null)
        {
            return new EncryptionScheme(ASN1Sequence.getInstance(obj));
        }

        return null;
    }

    public ASN1ObjectIdentifier getAlgorithm()
    {
        return algId.getAlgorithm();
    }

    public ASN1Encodable getParameters()
    {
        return algId.getParameters();
    }

    public ASN1Primitive toASN1Primitive()
    {
        return algId.toASN1Primitive();
    }
}
