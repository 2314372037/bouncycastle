package com.android.internal.org.bouncycastle.tsp.cms;

import java.net.URI;

import com.android.internal.org.bouncycastle.asn1.ASN1Boolean;
import com.android.internal.org.bouncycastle.asn1.ASN1IA5String;
import com.android.internal.org.bouncycastle.asn1.ASN1UTF8String;
import com.android.internal.org.bouncycastle.asn1.DERIA5String;
import com.android.internal.org.bouncycastle.asn1.DERUTF8String;
import com.android.internal.org.bouncycastle.asn1.cms.Attributes;
import com.android.internal.org.bouncycastle.asn1.cms.MetaData;
import com.android.internal.org.bouncycastle.cms.CMSException;
import com.android.internal.org.bouncycastle.operator.DigestCalculator;

public class CMSTimeStampedGenerator
{
    protected MetaData metaData;
    protected URI dataUri;

    /**
     * Set the dataURI to be included in message.
     *
     * @param dataUri URI for the data the initial message imprint digest is based on.
     */
    public void setDataUri(URI dataUri)
    {
        this.dataUri = dataUri;
    }

    /**
     * Set the MetaData for the generated message.
     *
     * @param hashProtected true if the MetaData should be included in first imprint calculation, false otherwise.
     * @param fileName optional file name, may be null.
     * @param mediaType optional media type, may be null.
     */
    public void setMetaData(boolean hashProtected, String fileName, String mediaType)
    {
        setMetaData(hashProtected, fileName, mediaType, null);
    }

    /**
     * Set the MetaData for the generated message.
     *
     * @param hashProtected true if the MetaData should be included in first imprint calculation, false otherwise.
     * @param fileName optional file name, may be null.
     * @param mediaType optional media type, may be null.
     * @param attributes optional attributes, may be null.
     */
    public void setMetaData(boolean hashProtected, String fileName, String mediaType, Attributes attributes)
    {
        ASN1UTF8String asn1FileName = null;

        if (fileName != null)
        {
            asn1FileName = new DERUTF8String(fileName);
        }

        ASN1IA5String asn1MediaType = null;

        if (mediaType != null)
        {
            asn1MediaType = new DERIA5String(mediaType);
        }

        setMetaData(hashProtected, asn1FileName, asn1MediaType, attributes);
    }

    private void setMetaData(boolean hashProtected, ASN1UTF8String fileName, ASN1IA5String mediaType, Attributes attributes)
    {
        this.metaData = new MetaData(ASN1Boolean.getInstance(hashProtected), fileName, mediaType, attributes);
    }

    /**
     * Initialise the passed in calculator with the MetaData for this message, if it is
     * required as part of the initial message imprint calculation. After initialisation the
     * calculator can then be used to calculate the initial message imprint digest for the first
     * timestamp.
     *
     * @param calculator the digest calculator to be initialised.
     * @throws CMSException if the MetaData is required and cannot be processed
     */
    public void initialiseMessageImprintDigestCalculator(DigestCalculator calculator)
        throws CMSException
    {
        MetaDataUtil util = new MetaDataUtil(metaData);

        util.initialiseMessageImprintDigestCalculator(calculator);
    }
}
