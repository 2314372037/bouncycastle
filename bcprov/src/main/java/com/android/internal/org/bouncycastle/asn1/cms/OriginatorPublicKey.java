package com.android.internal.org.bouncycastle.asn1.cms;

import com.android.internal.org.bouncycastle.asn1.ASN1BitString;
import com.android.internal.org.bouncycastle.asn1.ASN1EncodableVector;
import com.android.internal.org.bouncycastle.asn1.ASN1Object;
import com.android.internal.org.bouncycastle.asn1.ASN1Primitive;
import com.android.internal.org.bouncycastle.asn1.ASN1Sequence;
import com.android.internal.org.bouncycastle.asn1.ASN1TaggedObject;
import com.android.internal.org.bouncycastle.asn1.DERBitString;
import com.android.internal.org.bouncycastle.asn1.DERSequence;
import com.android.internal.org.bouncycastle.asn1.x509.AlgorithmIdentifier;

/**
 * <a href="https://tools.ietf.org/html/rfc5652#section-6.2.2">RFC 5652</a>:
 * Content encryption key delivery mechanisms.
 * <p>
 * <pre>
 * OriginatorPublicKey ::= SEQUENCE {
 *     algorithm AlgorithmIdentifier,
 *     publicKey BIT STRING 
 * }
 * </pre>
 */
public class OriginatorPublicKey
    extends ASN1Object
{
    private AlgorithmIdentifier algorithm;
    private ASN1BitString publicKey;

    public OriginatorPublicKey(
        AlgorithmIdentifier algorithm,
        byte[]              publicKey)
    {
        this.algorithm = algorithm;
        this.publicKey = new DERBitString(publicKey);
    }

    public OriginatorPublicKey(
        AlgorithmIdentifier algorithm,
        ASN1BitString publicKey)
    {
        this.algorithm = algorithm;
        this.publicKey = publicKey;
    }

    private OriginatorPublicKey(
        ASN1Sequence seq)
    {
        algorithm = AlgorithmIdentifier.getInstance(seq.getObjectAt(0));
        publicKey = (DERBitString)seq.getObjectAt(1);
    }
    
    /**
     * Return an OriginatorPublicKey object from a tagged object.
     *
     * @param obj the tagged object holding the object we want.
     * @param explicit true if the object is meant to be explicitly
     *              tagged false otherwise.
     * @exception IllegalArgumentException if the object held by the
     *          tagged object cannot be converted.
     */
    public static OriginatorPublicKey getInstance(
        ASN1TaggedObject    obj,
        boolean             explicit)
    {
        return new OriginatorPublicKey(ASN1Sequence.getInstance(obj, explicit));
    }
    
    /**
     * Return an OriginatorPublicKey object from the given object.
     * <p>
     * Accepted inputs:
     * <ul>
     * <li> null &rarr; null
     * <li> {@link OriginatorPublicKey} object
     * <li> {@link com.android.internal.org.bouncycastle.asn1.ASN1Sequence#getInstance(java.lang.Object) ASN1Sequence} input formats with OriginatorPublicKey structure inside
     * </ul>
     *
     * @param obj the object we want converted.
     * @exception IllegalArgumentException if the object cannot be converted.
     */
    public static OriginatorPublicKey getInstance(
        Object obj)
    {
        if (obj instanceof OriginatorPublicKey)
        {
            return (OriginatorPublicKey)obj;
        }
        
        if (obj != null)
        {
            return new OriginatorPublicKey(ASN1Sequence.getInstance(obj));
        }

        return null;
    } 

    public AlgorithmIdentifier getAlgorithm()
    {
        return algorithm;
    }

    /**
     * @deprecated Use {@link #getPublicKeyData()} instead.
     */
    public DERBitString getPublicKey()
    {
        return DERBitString.convert(publicKey);
    }

    public ASN1BitString getPublicKeyData()
    {
        return publicKey;
    }

    /** 
     * Produce an object suitable for an ASN1OutputStream.
     */
    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector v = new ASN1EncodableVector(2);

        v.add(algorithm);
        v.add(publicKey);

        return new DERSequence(v);
    }
}
