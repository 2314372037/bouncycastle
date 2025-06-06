package com.android.internal.org.bouncycastle.asn1.cmp;

import com.android.internal.org.bouncycastle.asn1.ASN1BitString;
import com.android.internal.org.bouncycastle.asn1.ASN1Encodable;
import com.android.internal.org.bouncycastle.asn1.ASN1EncodableVector;
import com.android.internal.org.bouncycastle.asn1.ASN1Object;
import com.android.internal.org.bouncycastle.asn1.ASN1Primitive;
import com.android.internal.org.bouncycastle.asn1.ASN1Sequence;
import com.android.internal.org.bouncycastle.asn1.ASN1TaggedObject;
import com.android.internal.org.bouncycastle.asn1.ASN1Util;
import com.android.internal.org.bouncycastle.asn1.DERBitString;
import com.android.internal.org.bouncycastle.asn1.DERSequence;
import com.android.internal.org.bouncycastle.asn1.DERTaggedObject;
import com.android.internal.org.bouncycastle.asn1.crmf.CertId;
import com.android.internal.org.bouncycastle.asn1.x509.AlgorithmIdentifier;

/**
 * <pre>
 * OOBCertHash ::= SEQUENCE {
 * hashAlg     [0] AlgorithmIdentifier     OPTIONAL,
 * certId      [1] CertId                  OPTIONAL,
 * hashVal         BIT STRING
 * -- hashVal is calculated over the DER encoding of the
 * -- self-signed certificate with the identifier certID.
 * }
 * </pre>
 */
public class OOBCertHash
    extends ASN1Object
{
    private final AlgorithmIdentifier hashAlg;
    private final CertId certId;
    private final ASN1BitString hashVal;

    private OOBCertHash(ASN1Sequence seq)
    {
        int index = seq.size() - 1;

        this.hashVal = ASN1BitString.getInstance(seq.getObjectAt(index--));

        AlgorithmIdentifier hashAlg = null;
        CertId certId = null;

        for (int i = index; i >= 0; i--)
        {
            ASN1TaggedObject tObj = (ASN1TaggedObject)seq.getObjectAt(i);

            if (tObj.hasContextTag(0))
            {
                hashAlg = AlgorithmIdentifier.getInstance(tObj, true);
            }
            else if (tObj.hasContextTag(1))
            {
                certId = CertId.getInstance(tObj, true);
            }
            else
            {
                throw new IllegalArgumentException("unknown tag " + ASN1Util.getTagText(tObj));
            }
        }

        this.hashAlg = hashAlg;
        this.certId = certId;
    }

    public OOBCertHash(AlgorithmIdentifier hashAlg, CertId certId, byte[] hashVal)
    {
        this(hashAlg, certId, new DERBitString(hashVal));
    }

    public OOBCertHash(AlgorithmIdentifier hashAlg, CertId certId, DERBitString hashVal)
    {
        this.hashAlg = hashAlg;
        this.certId = certId;
        this.hashVal = hashVal;
    }

    public static OOBCertHash getInstance(Object o)
    {
        if (o instanceof OOBCertHash)
        {
            return (OOBCertHash)o;
        }

        if (o != null)
        {
            return new OOBCertHash(ASN1Sequence.getInstance(o));
        }

        return null;
    }

    public AlgorithmIdentifier getHashAlg()
    {
        return hashAlg;
    }

    public CertId getCertId()
    {
        return certId;
    }

    public ASN1BitString getHashVal()
    {
        return hashVal;
    }

    /**
     * <pre>
     * OOBCertHash ::= SEQUENCE {
     *                      hashAlg     [0] AlgorithmIdentifier     OPTIONAL,
     *                      certId      [1] CertId                  OPTIONAL,
     *                      hashVal         BIT STRING
     *                      -- hashVal is calculated over the DER encoding of the
     *                      -- self-signed certificate with the identifier certID.
     *       }
     * </pre>
     *
     * @return a basic ASN.1 object representation.
     */
    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector v = new ASN1EncodableVector(3);

        addOptional(v, 0, hashAlg);
        addOptional(v, 1, certId);

        v.add(hashVal);

        return new DERSequence(v);
    }

    private void addOptional(ASN1EncodableVector v, int tagNo, ASN1Encodable obj)
    {
        if (obj != null)
        {
            v.add(new DERTaggedObject(true, tagNo, obj));
        }
    }
}
