package com.android.internal.org.bouncycastle.dvcs;

import com.android.internal.org.bouncycastle.asn1.ASN1Encodable;
import com.android.internal.org.bouncycastle.asn1.ASN1OctetString;
import com.android.internal.org.bouncycastle.asn1.ASN1Sequence;
import com.android.internal.org.bouncycastle.asn1.cms.ContentInfo;
import com.android.internal.org.bouncycastle.asn1.cms.SignedData;
import com.android.internal.org.bouncycastle.asn1.dvcs.DVCSObjectIdentifiers;
import com.android.internal.org.bouncycastle.asn1.dvcs.ServiceType;
import com.android.internal.org.bouncycastle.asn1.x509.GeneralName;
import com.android.internal.org.bouncycastle.cms.CMSSignedData;

/**
 * DVCRequest is general request to DVCS (RFC 3029).
 * It represents requests for all types of services.
 * Requests for different services differ in DVCData structure.
 */
public class DVCSRequest
    extends DVCSMessage
{
    private com.android.internal.org.bouncycastle.asn1.dvcs.DVCSRequest asn1;
    private DVCSRequestInfo reqInfo;
    private DVCSRequestData data;

    /**
     * Constructs DVCRequest from CMS SignedData object.
     *
     * @param signedData the CMS SignedData object containing the request
     * @throws DVCSConstructionException
     */
    public DVCSRequest(CMSSignedData signedData)
        throws DVCSConstructionException
    {
        this(SignedData.getInstance(signedData.toASN1Structure().getContent()).getEncapContentInfo());
    }

    /**
     * Construct a DVCS Request from a ContentInfo
     *
     * @param contentInfo the contentInfo representing the DVCSRequest
     * @throws DVCSConstructionException
     */
    public DVCSRequest(ContentInfo contentInfo)
        throws DVCSConstructionException
    {
        super(contentInfo);

        if (!DVCSObjectIdentifiers.id_ct_DVCSRequestData.equals(contentInfo.getContentType()))
        {
            throw new DVCSConstructionException("ContentInfo not a DVCS Request");
        }

        try
        {
            if (contentInfo.getContent().toASN1Primitive() instanceof ASN1Sequence)
            {
                this.asn1 = com.android.internal.org.bouncycastle.asn1.dvcs.DVCSRequest.getInstance(contentInfo.getContent());
            }
            else
            {
                this.asn1 = com.android.internal.org.bouncycastle.asn1.dvcs.DVCSRequest.getInstance(ASN1OctetString.getInstance(contentInfo.getContent()).getOctets());
            }
        }
        catch (Exception e)
        {
            throw new DVCSConstructionException("Unable to parse content: " + e.getMessage(), e);
        }

        this.reqInfo = new DVCSRequestInfo(asn1.getRequestInformation());

        int service = reqInfo.getServiceType();
        if (service == ServiceType.CPD.getValue().intValue())
        {
            this.data = new CPDRequestData(asn1.getData());
        }
        else if (service == ServiceType.VSD.getValue().intValue())
        {
            this.data = new VSDRequestData(asn1.getData());
        }
        else if (service == ServiceType.VPKC.getValue().intValue())
        {
            this.data = new VPKCRequestData(asn1.getData());
        }
        else if (service == ServiceType.CCPD.getValue().intValue())
        {
            this.data = new CCPDRequestData(asn1.getData());
        }
        else
        {
            throw new DVCSConstructionException("Unknown service type: " + service);
        }
    }

    /**
     * Return the ASN.1 DVCSRequest structure making up the body of this request.
     *
     * @return an com.android.internal.org.bouncycastle.asn1.dvcs.DVCSRequest object.
     */
    public ASN1Encodable getContent()
    {
        return asn1;
    }

    /**
     * Get RequestInformation envelope.
     *
     * @return the request info object.
     */
    public DVCSRequestInfo getRequestInfo()
    {
        return reqInfo;
    }

    /**
     * Get data of DVCRequest.
     * Depending on type of the request it could be different subclasses of DVCRequestData.
     *
     * @return the request Data object.
     */
    public DVCSRequestData getData()
    {
        return data;
    }

    /**
     * Get the transaction identifier of request.
     *
     * @return the GeneralName representing the Transaction Identifier.
     */
    public GeneralName getTransactionIdentifier()
    {
        return asn1.getTransactionIdentifier();
    }
}
