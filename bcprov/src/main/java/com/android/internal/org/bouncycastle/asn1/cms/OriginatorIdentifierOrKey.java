package com.android.internal.org.bouncycastle.asn1.cms;

import com.android.internal.org.bouncycastle.asn1.ASN1Choice;
import com.android.internal.org.bouncycastle.asn1.ASN1Encodable;
import com.android.internal.org.bouncycastle.asn1.ASN1Object;
import com.android.internal.org.bouncycastle.asn1.ASN1OctetString;
import com.android.internal.org.bouncycastle.asn1.ASN1Primitive;
import com.android.internal.org.bouncycastle.asn1.ASN1Sequence;
import com.android.internal.org.bouncycastle.asn1.ASN1TaggedObject;
import com.android.internal.org.bouncycastle.asn1.BERTags;
import com.android.internal.org.bouncycastle.asn1.DERTaggedObject;
import com.android.internal.org.bouncycastle.asn1.x509.SubjectKeyIdentifier;

/**
 * <a href="https://tools.ietf.org/html/rfc5652#section-6.2.2">RFC 5652</a>:
 * Content encryption key delivery mechanisms.
 * <pre>
 * OriginatorIdentifierOrKey ::= CHOICE {
 *     issuerAndSerialNumber IssuerAndSerialNumber,
 *     subjectKeyIdentifier [0] SubjectKeyIdentifier,
 *     originatorKey [1] OriginatorPublicKey 
 * }
 *
 * SubjectKeyIdentifier ::= OCTET STRING
 * </pre>
 */
public class OriginatorIdentifierOrKey
    extends ASN1Object
    implements ASN1Choice
{
    private ASN1Encodable id;

    public OriginatorIdentifierOrKey(
        IssuerAndSerialNumber id)
    {
        this.id = id;
    }

    /**
     * @deprecated use version taking a SubjectKeyIdentifier
     */
    public OriginatorIdentifierOrKey(
        ASN1OctetString id)
    {
        this(new SubjectKeyIdentifier(id.getOctets()));
    }

    public OriginatorIdentifierOrKey(
        SubjectKeyIdentifier id)
    {
        this.id = new DERTaggedObject(false, 0, id);
    }

    public OriginatorIdentifierOrKey(
        OriginatorPublicKey id)
    {
        this.id = new DERTaggedObject(false, 1, id);
    }

    /**
     * @deprecated use more specific version
     */
    public OriginatorIdentifierOrKey(
        ASN1Primitive id)
    {
        this.id = id;
    }

    /**
     * Return an OriginatorIdentifierOrKey object from a tagged object.
     *
     * @param o the tagged object holding the object we want.
     * @param explicit true if the object is meant to be explicitly
     *              tagged false otherwise.
     * @exception IllegalArgumentException if the object held by the
     *          tagged object cannot be converted.
     */
    public static OriginatorIdentifierOrKey getInstance(
        ASN1TaggedObject    o,
        boolean             explicit)
    {
        if (!explicit)
        {
            throw new IllegalArgumentException(
                    "Can't implicitly tag OriginatorIdentifierOrKey");
        }

        return getInstance(o.getExplicitBaseObject());
    }
    
    /**
     * Return an OriginatorIdentifierOrKey object from the given object.
     * <p>
     * Accepted inputs:
     * <ul>
     * <li> null &rarr; null
     * <li> {@link OriginatorIdentifierOrKey} object
     * <li> {@link IssuerAndSerialNumber} object
     * <li> {@link com.android.internal.org.bouncycastle.asn1.ASN1TaggedObject#getInstance(java.lang.Object) ASN1TaggedObject} input formats with IssuerAndSerialNumber structure inside
     * </ul>
     *
     * @param o the object we want converted.
     * @exception IllegalArgumentException if the object cannot be converted.
     */
    public static OriginatorIdentifierOrKey getInstance(Object o)
    {
        if (o == null || o instanceof OriginatorIdentifierOrKey)
        {
            return (OriginatorIdentifierOrKey)o;
        }

        if (o instanceof IssuerAndSerialNumber)
        {
            return new OriginatorIdentifierOrKey((IssuerAndSerialNumber)o);
        }

        if (o instanceof ASN1Sequence)
        {
            return new OriginatorIdentifierOrKey(IssuerAndSerialNumber.getInstance(o));
        }

        if (o instanceof ASN1TaggedObject)
        {
            ASN1TaggedObject taggedObject = (ASN1TaggedObject)o;

            if (taggedObject.hasContextTag(0))
            {
                return new OriginatorIdentifierOrKey(SubjectKeyIdentifier.getInstance(taggedObject, false));
            }

            if (taggedObject.hasContextTag(1))
            {
                return new OriginatorIdentifierOrKey(OriginatorPublicKey.getInstance(taggedObject, false));
            }
        }

        throw new IllegalArgumentException("Invalid OriginatorIdentifierOrKey: " + o.getClass().getName());
    }

    public ASN1Encodable getId()
    {
        return id;
    }

    public IssuerAndSerialNumber getIssuerAndSerialNumber()
    {
        if (id instanceof IssuerAndSerialNumber)
        {
            return (IssuerAndSerialNumber)id;
        }

        return null;
    }

    public SubjectKeyIdentifier getSubjectKeyIdentifier()
    {
        if (id instanceof ASN1TaggedObject)
        {
            ASN1TaggedObject taggedObject = (ASN1TaggedObject)id;
            if (taggedObject.hasContextTag(0))
            {
                return SubjectKeyIdentifier.getInstance(taggedObject, false);
            }
        }

        return null;
    }

    public OriginatorPublicKey getOriginatorKey()
    {
        if (id instanceof ASN1TaggedObject)
        {
            ASN1TaggedObject taggedObject = (ASN1TaggedObject)id;
            if (taggedObject.hasContextTag(1))
            {
                return OriginatorPublicKey.getInstance(taggedObject, false);
            }
        }

        return null;
    }

    /**
     * Produce an object suitable for an ASN1OutputStream.
     */
    public ASN1Primitive toASN1Primitive()
    {
        return id.toASN1Primitive();
    }
}
