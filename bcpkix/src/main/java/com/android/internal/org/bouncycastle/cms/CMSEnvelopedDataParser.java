package com.android.internal.org.bouncycastle.cms;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;

import com.android.internal.org.bouncycastle.asn1.ASN1OctetStringParser;
import com.android.internal.org.bouncycastle.asn1.ASN1SequenceParser;
import com.android.internal.org.bouncycastle.asn1.ASN1Set;
import com.android.internal.org.bouncycastle.asn1.BERTags;
import com.android.internal.org.bouncycastle.asn1.cms.AttributeTable;
import com.android.internal.org.bouncycastle.asn1.cms.EncryptedContentInfoParser;
import com.android.internal.org.bouncycastle.asn1.cms.EnvelopedDataParser;
import com.android.internal.org.bouncycastle.asn1.cms.OriginatorInfo;
import com.android.internal.org.bouncycastle.asn1.x509.AlgorithmIdentifier;

/**
 * Parsing class for an CMS Enveloped Data object from an input stream.
 * <p>
 * Note: that because we are in a streaming mode only one recipient can be tried and it is important 
 * that the methods on the parser are called in the appropriate order.
 * </p>
 * <p>
 * Example of use - assuming the first recipient matches the private key we have.
 * <pre>
 *      CMSEnvelopedDataParser     ep = new CMSEnvelopedDataParser(inputStream);
 *
 *      RecipientInformationStore  recipients = ep.getRecipientInfos();
 *
 *      Collection  c = recipients.getRecipients();
 *      Iterator    it = c.iterator();
 *      
 *      if (it.hasNext())
 *      {
 *          RecipientInformation   recipient = (RecipientInformation)it.next();
 *
 *          CMSTypedStream recData = recipient.getContentStream(new JceKeyTransEnvelopedRecipient(privateKey).setProvider("BC"));
 *          
 *          processDataStream(recData.getContentStream());
 *      }
 *  </pre>
 *  Note: this class does not introduce buffering - if you are processing large files you should create
 *  the parser with:
 *  <pre>
 *          CMSEnvelopedDataParser     ep = new CMSEnvelopedDataParser(new BufferedInputStream(inputStream, bufSize));
 *  </pre>
 *  where bufSize is a suitably large buffer size.
 */
public class CMSEnvelopedDataParser
    extends CMSContentInfoParser
{
    RecipientInformationStore recipientInfoStore;
    EnvelopedDataParser envelopedData;
    
    private AlgorithmIdentifier encAlg;
    private AttributeTable unprotectedAttributes;
    private boolean attrNotRead;
    private OriginatorInformation  originatorInfo;

    public CMSEnvelopedDataParser(
        byte[]    envelopedData) 
        throws CMSException, IOException
    {
        this(new ByteArrayInputStream(envelopedData));
    }

    public CMSEnvelopedDataParser(
        InputStream    envelopedData) 
        throws CMSException, IOException
    {
        super(envelopedData);

        this.attrNotRead = true;
        this.envelopedData = new EnvelopedDataParser((ASN1SequenceParser)_contentInfo.getContent(BERTags.SEQUENCE));

        // TODO Validate version?
        //ASN1Integer version = this._envelopedData.getVersion();

        OriginatorInfo info = this.envelopedData.getOriginatorInfo();

        if (info != null)
        {
            this.originatorInfo = new OriginatorInformation(info);
        }

        //
        // read the recipients
        //
        ASN1Set recipientInfos = ASN1Set.getInstance(this.envelopedData.getRecipientInfos().toASN1Primitive());

        //
        // read the encrypted content info
        //
        EncryptedContentInfoParser encInfo = this.envelopedData.getEncryptedContentInfo();
        this.encAlg = encInfo.getContentEncryptionAlgorithm();
        CMSReadable readable = new CMSProcessableInputStream(
            ((ASN1OctetStringParser)encInfo.getEncryptedContent(BERTags.OCTET_STRING)).getOctetStream());
        CMSSecureReadable secureReadable = new CMSEnvelopedHelper.CMSAuthEnveSecureReadable(
            this.encAlg, encInfo.getContentType(), readable);

        //
        // build the RecipientInformationStore
        //
        this.recipientInfoStore = CMSEnvelopedHelper.buildRecipientInformationStore(
            recipientInfos, this.encAlg, secureReadable);
    }

    /**
     * return the object identifier for the content encryption algorithm.
     */
    public String getEncryptionAlgOID()
    {
        return encAlg.getAlgorithm().toString();
    }

    /**
     * return the ASN.1 encoded encryption algorithm parameters, or null if
     * there aren't any.
     */
    public byte[] getEncryptionAlgParams()
    {
        try
        {
            return CMSUtils.encodeObj(encAlg.getParameters());
        }
        catch (Exception e)
        {
            throw new RuntimeException("exception getting encryption parameters " + e);
        }
    }

    /**
     * Return the content encryption algorithm details for the data in this object.
     *
     * @return AlgorithmIdentifier representing the content encryption algorithm.
     */
    public AlgorithmIdentifier getContentEncryptionAlgorithm()
    {
        return encAlg;
    }

    /**
     * Return the originator information associated with this message if present.
     *
     * @return OriginatorInformation, null if not present.
     */
    public OriginatorInformation getOriginatorInfo()
    {
        return originatorInfo;
    }

    /**
     * return a store of the intended recipients for this message
     */
    public RecipientInformationStore getRecipientInfos()
    {
        return recipientInfoStore;
    }

    /**
     * return a table of the unprotected attributes indexed by
     * the OID of the attribute.
     * @exception IOException 
     */
    public AttributeTable getUnprotectedAttributes() 
        throws IOException
    {
        if (unprotectedAttributes == null && attrNotRead)
        {
            attrNotRead = false;
            unprotectedAttributes = CMSUtils.getAttributesTable(envelopedData.getUnprotectedAttrs());
        }

        return unprotectedAttributes;
    }
}
