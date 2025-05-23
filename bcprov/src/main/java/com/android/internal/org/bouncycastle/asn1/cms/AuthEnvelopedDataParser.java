package com.android.internal.org.bouncycastle.asn1.cms;

import java.io.IOException;

import com.android.internal.org.bouncycastle.asn1.ASN1Encodable;
import com.android.internal.org.bouncycastle.asn1.ASN1Integer;
import com.android.internal.org.bouncycastle.asn1.ASN1OctetString;
import com.android.internal.org.bouncycastle.asn1.ASN1ParsingException;
import com.android.internal.org.bouncycastle.asn1.ASN1SequenceParser;
import com.android.internal.org.bouncycastle.asn1.ASN1SetParser;
import com.android.internal.org.bouncycastle.asn1.ASN1TaggedObjectParser;
import com.android.internal.org.bouncycastle.asn1.ASN1Util;
import com.android.internal.org.bouncycastle.asn1.BERTags;

/**
 * Parse {@link AuthEnvelopedData} input stream.
 * 
 * <pre>
 * AuthEnvelopedData ::= SEQUENCE {
 *   version CMSVersion,
 *   originatorInfo [0] IMPLICIT OriginatorInfo OPTIONAL,
 *   recipientInfos RecipientInfos,
 *   authEncryptedContentInfo EncryptedContentInfo,
 *   authAttrs [1] IMPLICIT AuthAttributes OPTIONAL,
 *   mac MessageAuthenticationCode,
 *   unauthAttrs [2] IMPLICIT UnauthAttributes OPTIONAL }
 * </pre>
 */
public class AuthEnvelopedDataParser
{
    private ASN1SequenceParser seq;
    private ASN1Integer version;
    private ASN1Encodable nextObject;
    private boolean originatorInfoCalled;
    private boolean isData;

    public AuthEnvelopedDataParser(ASN1SequenceParser seq) throws IOException
    {
        this.seq = seq;

        // "It MUST be set to 0."
        this.version = ASN1Integer.getInstance(seq.readObject());
        if (!version.hasValue(0))
        {
            throw new ASN1ParsingException("AuthEnvelopedData version number must be 0");
        }
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

    public EncryptedContentInfoParser getAuthEncryptedContentInfo()
        throws IOException
    {
        if (nextObject == null)
        {
            nextObject = seq.readObject();
        }

        if (nextObject != null)
        {
            ASN1SequenceParser o = (ASN1SequenceParser) nextObject;
            nextObject = null;
            EncryptedContentInfoParser encryptedContentInfoParser = new EncryptedContentInfoParser(o);
            isData = CMSObjectIdentifiers.data.equals(encryptedContentInfoParser.getContentType());
            return encryptedContentInfoParser;
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
            return (ASN1SetParser)ASN1Util.parseContextBaseUniversal(o, 1, false, BERTags.SET_OF);
        }

        // "The authAttrs MUST be present if the content type carried in
        // EncryptedContentInfo is not id-data."
        if (!isData)
        {
            throw new ASN1ParsingException("authAttrs must be present with non-data content");
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
            ASN1TaggedObjectParser o = (ASN1TaggedObjectParser)nextObject;
            nextObject = null;
            return (ASN1SetParser)ASN1Util.parseContextBaseUniversal(o, 2, false, BERTags.SET_OF);
        }

        return null;
    }
}
