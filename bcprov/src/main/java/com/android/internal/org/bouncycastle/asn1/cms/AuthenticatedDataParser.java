package com.android.internal.org.bouncycastle.asn1.cms;

import java.io.IOException;

import com.android.internal.org.bouncycastle.asn1.ASN1Encodable;
import com.android.internal.org.bouncycastle.asn1.ASN1Integer;
import com.android.internal.org.bouncycastle.asn1.ASN1OctetString;
import com.android.internal.org.bouncycastle.asn1.ASN1SequenceParser;
import com.android.internal.org.bouncycastle.asn1.ASN1SetParser;
import com.android.internal.org.bouncycastle.asn1.ASN1TaggedObject;
import com.android.internal.org.bouncycastle.asn1.ASN1TaggedObjectParser;
import com.android.internal.org.bouncycastle.asn1.ASN1Util;
import com.android.internal.org.bouncycastle.asn1.BERTags;
import com.android.internal.org.bouncycastle.asn1.x509.AlgorithmIdentifier;

/**
 * Parse {@link AuthenticatedData} stream.
 * <pre>
 * AuthenticatedData ::= SEQUENCE {
 *       version CMSVersion,
 *       originatorInfo [0] IMPLICIT OriginatorInfo OPTIONAL,
 *       recipientInfos RecipientInfos,
 *       macAlgorithm MessageAuthenticationCodeAlgorithm,
 *       digestAlgorithm [1] DigestAlgorithmIdentifier OPTIONAL,
 *       encapContentInfo EncapsulatedContentInfo,
 *       authAttrs [2] IMPLICIT AuthAttributes OPTIONAL,
 *       mac MessageAuthenticationCode,
 *       unauthAttrs [3] IMPLICIT UnauthAttributes OPTIONAL }
 *
 * AuthAttributes ::= SET SIZE (1..MAX) OF Attribute
 *
 * UnauthAttributes ::= SET SIZE (1..MAX) OF Attribute
 *
 * MessageAuthenticationCode ::= OCTET STRING
 * </pre>
 */
public class AuthenticatedDataParser
{
    private ASN1SequenceParser seq;
    private ASN1Integer version;
    private ASN1Encodable nextObject;
    private boolean originatorInfoCalled;

    public AuthenticatedDataParser(
        ASN1SequenceParser seq)
        throws IOException
    {
        this.seq = seq;
        this.version = ASN1Integer.getInstance(seq.readObject());
    }

    public ASN1Integer getVersion()
    {
        return version;
    }

    public OriginatorInfo getOriginatorInfo()
        throws IOException
    {
        originatorInfoCalled = true;

        if (nextObject == null)
        {
            nextObject = seq.readObject();
        }

        if (nextObject instanceof ASN1TaggedObjectParser)
        {
            ASN1TaggedObjectParser o = (ASN1TaggedObjectParser)nextObject;
            if (o.hasContextTag(0))
            {
                ASN1SequenceParser originatorInfo = (ASN1SequenceParser)o.parseBaseUniversal(false, BERTags.SEQUENCE);
                nextObject = null;
                return OriginatorInfo.getInstance(originatorInfo.getLoadedObject());
            }
        }

        return null;
    }

    public ASN1SetParser getRecipientInfos()
        throws IOException
    {
        if (!originatorInfoCalled)
        {
            getOriginatorInfo();
        }

        if (nextObject == null)
        {
            nextObject = seq.readObject();
        }

        ASN1SetParser recipientInfos = (ASN1SetParser)nextObject;
        nextObject = null;
        return recipientInfos;
    }

    public AlgorithmIdentifier getMacAlgorithm()
        throws IOException
    {
        if (nextObject == null)
        {
            nextObject = seq.readObject();
        }

        if (nextObject != null)
        {
            ASN1SequenceParser o = (ASN1SequenceParser)nextObject;
            nextObject = null;
            return AlgorithmIdentifier.getInstance(o.toASN1Primitive());
        }

        return null;
    }

    public AlgorithmIdentifier getDigestAlgorithm()
        throws IOException
    {
        if (nextObject == null)
        {
            nextObject = seq.readObject();
        }

        if (nextObject instanceof ASN1TaggedObjectParser)
        {
            AlgorithmIdentifier obj = AlgorithmIdentifier.getInstance((ASN1TaggedObject)nextObject.toASN1Primitive(), false);
            nextObject = null;
            return obj;
        }

        return null;
    }

    public ContentInfoParser getEncapsulatedContentInfo()
        throws IOException
    {
        if (nextObject == null)
        {
            nextObject = seq.readObject();
        }

        if (nextObject != null)
        {
            ASN1SequenceParser o = (ASN1SequenceParser)nextObject;
            nextObject = null;
            return new ContentInfoParser(o);
        }

        return null;
    }

    public ASN1SetParser getAuthAttrs()
        throws IOException
    {
        if (nextObject == null)
        {
            nextObject = seq.readObject();
        }

        if (nextObject instanceof ASN1TaggedObjectParser)
        {
            ASN1TaggedObjectParser o = (ASN1TaggedObjectParser)nextObject;
            nextObject = null;
            return (ASN1SetParser)ASN1Util.parseContextBaseUniversal(o, 2, false, BERTags.SET_OF);
        }

        return null;
    }

    public ASN1OctetString getMac()
        throws IOException
    {
        if (nextObject == null)
        {
            nextObject = seq.readObject();
        }

        ASN1Encodable o = nextObject;
        nextObject = null;

        return ASN1OctetString.getInstance(o.toASN1Primitive());
    }

    public ASN1SetParser getUnauthAttrs()
        throws IOException
    {
        if (nextObject == null)
        {
            nextObject = seq.readObject();
        }

        if (nextObject != null)
        {
            ASN1TaggedObject o = (ASN1TaggedObject)nextObject;
            nextObject = null;
            return (ASN1SetParser)ASN1Util.parseContextBaseUniversal(o, 3, false, BERTags.SET_OF);
        }

        return null;
    }
}
