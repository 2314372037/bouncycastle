package com.android.internal.org.bouncycastle.dvcs;

import com.android.internal.org.bouncycastle.asn1.ASN1Encodable;
import com.android.internal.org.bouncycastle.asn1.ASN1OctetString;
import com.android.internal.org.bouncycastle.asn1.ASN1Sequence;
import com.android.internal.org.bouncycastle.asn1.cms.ContentInfo;
import com.android.internal.org.bouncycastle.asn1.cms.SignedData;
import com.android.internal.org.bouncycastle.asn1.dvcs.DVCSObjectIdentifiers;
import com.android.internal.org.bouncycastle.cms.CMSSignedData;

/**
 * DVCResponse is general response to DVCS (RFC 3029).
 * It represents responses for all types of services.
 */
public class DVCSResponse
    extends DVCSMessage
{
    private com.android.internal.org.bouncycastle.asn1.dvcs.DVCSResponse asn1;

    /**
     * Constructs DVCResponse from CMS SignedData object.
     *
     * @param signedData the CMS SignedData object containing the request
     * @throws com.android.internal.org.bouncycastle.dvcs.DVCSConstructionException
     */
    public DVCSResponse(CMSSignedData signedData)
        throws DVCSConstructionException
    {
        this(SignedData.getInstance(signedData.toASN1Structure().getContent()).getEncapContentInfo());
    }

    /**
     * Construct a DVCS Response from a ContentInfo
     *
     * @param contentInfo the contentInfo representing the DVCSRequest
     * @throws com.android.internal.org.bouncycastle.dvcs.DVCSConstructionException
     */
    public DVCSResponse(ContentInfo contentInfo)
        throws DVCSConstructionException
    {
        super(contentInfo);

        if (!DVCSObjectIdentifiers.id_ct_DVCSResponseData.equals(contentInfo.getContentType()))
        {
            throw new DVCSConstructionException("ContentInfo not a DVCS Response");
        }

        try
        {
            if (contentInfo.getContent().toASN1Primitive() instanceof ASN1Sequence)
            {
                this.asn1 = com.android.internal.org.bouncycastle.asn1.dvcs.DVCSResponse.getInstance(contentInfo.getContent());
            }
            else
            {
                this.asn1 = com.android.internal.org.bouncycastle.asn1.dvcs.DVCSResponse.getInstance(ASN1OctetString.getInstance(contentInfo.getContent()).getOctets());
            }
        }
        catch (Exception e)
        {
            throw new DVCSConstructionException("Unable to parse content: " + e.getMessage(), e);
        }
    }

    /**
     * Return the ASN.1 DVCSResponse structure making up the body of this response.
     *
     * @return an com.android.internal.org.bouncycastle.asn1.dvcs.DVCSResponse object.
     */
    public ASN1Encodable getContent()
    {
        return asn1;
    }
}
