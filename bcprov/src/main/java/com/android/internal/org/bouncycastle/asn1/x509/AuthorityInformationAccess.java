package com.android.internal.org.bouncycastle.asn1.x509;

import com.android.internal.org.bouncycastle.asn1.ASN1Object;
import com.android.internal.org.bouncycastle.asn1.ASN1ObjectIdentifier;
import com.android.internal.org.bouncycastle.asn1.ASN1Primitive;
import com.android.internal.org.bouncycastle.asn1.ASN1Sequence;
import com.android.internal.org.bouncycastle.asn1.DERSequence;

/**
 * The AuthorityInformationAccess object.
 * <pre>
 * id-pe-authorityInfoAccess OBJECT IDENTIFIER ::= { id-pe 1 }
 *
 * AuthorityInfoAccessSyntax  ::=
 *      SEQUENCE SIZE (1..MAX) OF AccessDescription
 * AccessDescription  ::=  SEQUENCE {
 *       accessMethod          OBJECT IDENTIFIER,
 *       accessLocation        GeneralName  }
 *
 * id-ad OBJECT IDENTIFIER ::= { id-pkix 48 }
 * id-ad-caIssuers OBJECT IDENTIFIER ::= { id-ad 2 }
 * id-ad-ocsp OBJECT IDENTIFIER ::= { id-ad 1 }
 * </pre>
 */
public class AuthorityInformationAccess
    extends ASN1Object
{
    private AccessDescription[]    descriptions;

    private static AccessDescription[] copy(AccessDescription[] descriptions)
    {
        AccessDescription[] result = new AccessDescription[descriptions.length];
        System.arraycopy(descriptions, 0, result, 0, descriptions.length);
        return result;
    }

    public static AuthorityInformationAccess getInstance(
        Object  obj)
    {
        if (obj instanceof AuthorityInformationAccess)
        {
            return (AuthorityInformationAccess)obj;
        }

        if (obj != null)
        {
            return new AuthorityInformationAccess(ASN1Sequence.getInstance(obj));
        }

        return null;
    }

    public static AuthorityInformationAccess fromExtensions(Extensions extensions)
    {
        return getInstance(Extensions.getExtensionParsedValue(extensions, Extension.authorityInfoAccess));
    }

    private AuthorityInformationAccess(
        ASN1Sequence   seq)
    {
        if (seq.size() < 1) 
        {
            throw new IllegalArgumentException("sequence may not be empty");
        }

        descriptions = new AccessDescription[seq.size()];

        for (int i = 0; i != seq.size(); i++)
        {
            descriptions[i] = AccessDescription.getInstance(seq.getObjectAt(i));
        }
    }

    public AuthorityInformationAccess(
        AccessDescription description)
    {
        this.descriptions = new AccessDescription[]{ description };
    }

    public AuthorityInformationAccess(
        AccessDescription[] descriptions)
    {
        this.descriptions = copy(descriptions);
    }

    /**
     * create an AuthorityInformationAccess with the oid and location provided.
     */
    public AuthorityInformationAccess(
        ASN1ObjectIdentifier oid,
        GeneralName location)
    {
        this(new AccessDescription(oid, location));
    }

    /**
     * 
     * @return the access descriptions contained in this object.
     */
    public AccessDescription[] getAccessDescriptions()
    {
        return copy(descriptions);
    }

    public ASN1Primitive toASN1Primitive()
    {
        return new DERSequence(descriptions);
    }

    public String toString()
    {
        return ("AuthorityInformationAccess: Oid(" + this.descriptions[0].getAccessMethod().getId() + ")");
    }
}
