package com.android.internal.org.bouncycastle.dvcs;

import java.io.IOException;
import java.math.BigInteger;

import com.android.internal.org.bouncycastle.asn1.ASN1Encodable;
import com.android.internal.org.bouncycastle.asn1.ASN1ObjectIdentifier;
import com.android.internal.org.bouncycastle.asn1.cms.ContentInfo;
import com.android.internal.org.bouncycastle.asn1.dvcs.DVCSObjectIdentifiers;
import com.android.internal.org.bouncycastle.asn1.dvcs.DVCSRequestInformationBuilder;
import com.android.internal.org.bouncycastle.asn1.dvcs.Data;
import com.android.internal.org.bouncycastle.asn1.x509.ExtensionsGenerator;
import com.android.internal.org.bouncycastle.asn1.x509.GeneralName;
import com.android.internal.org.bouncycastle.asn1.x509.GeneralNames;
import com.android.internal.org.bouncycastle.cms.CMSSignedDataGenerator;

/**
 * Common base class for client DVCRequest builders.
 * This class aims at DVCSRequestInformation and TransactionIdentifier construction,
 * and its subclasses - for Data field construction (as it is specific for the requested service).
 */
public abstract class DVCSRequestBuilder
{
    private final ExtensionsGenerator extGenerator = new ExtensionsGenerator();
    private final CMSSignedDataGenerator signedDataGen = new CMSSignedDataGenerator();

    protected final DVCSRequestInformationBuilder requestInformationBuilder;

    protected DVCSRequestBuilder(DVCSRequestInformationBuilder requestInformationBuilder)
    {
        this.requestInformationBuilder = requestInformationBuilder;
    }

    /**
     * Set a nonce for this request,
     *
     * @param nonce
     */
    public void setNonce(BigInteger nonce)
    {
        requestInformationBuilder.setNonce(nonce);
    }

    /**
     * Set requester name.
     *
     * @param requester
     */
    public void setRequester(GeneralName requester)
    {
        requestInformationBuilder.setRequester(requester);
    }

    /**
     * Set DVCS name to generated requests.
     *
     * @param dvcs
     */
    public void setDVCS(GeneralName dvcs)
    {
        requestInformationBuilder.setDVCS(dvcs);
    }

    /**
     * Set DVCS name to generated requests.
     *
     * @param dvcs
     */
    public void setDVCS(GeneralNames dvcs)
    {
        requestInformationBuilder.setDVCS(dvcs);
    }

    /**
     * Set data location to generated requests.
     *
     * @param dataLocation
     */
    public void setDataLocations(GeneralName dataLocation)
    {
        requestInformationBuilder.setDataLocations(dataLocation);
    }

    /**
     * Set data location to generated requests.
     *
     * @param dataLocations
     */
    public void setDataLocations(GeneralNames dataLocations)
    {
        requestInformationBuilder.setDataLocations(dataLocations);
    }

    /**
     * Add a given extension field.
     *
     * @param oid the OID defining the extension type.
     * @param isCritical true if the extension is critical, false otherwise.
     * @param value the ASN.1 structure that forms the extension's value.
     * @throws DVCSException if there is an issue encoding the extension for adding.
     */
    public void addExtension(
        ASN1ObjectIdentifier oid,
        boolean isCritical,
        ASN1Encodable value)
        throws DVCSException
    {
        try
        {
            extGenerator.addExtension(oid, isCritical, value);
        }
        catch (IOException e)
        {
            throw new DVCSException("cannot encode extension: " + e.getMessage(), e);
        }
    }

    protected DVCSRequest createDVCRequest(Data data)
        throws DVCSException
    {
        if (!extGenerator.isEmpty())
        {
            requestInformationBuilder.setExtensions(extGenerator.generate());
        }

        com.android.internal.org.bouncycastle.asn1.dvcs.DVCSRequest request = new com.android.internal.org.bouncycastle.asn1.dvcs.DVCSRequest(requestInformationBuilder.build(), data);

        return new DVCSRequest(new ContentInfo(DVCSObjectIdentifiers.id_ct_DVCSRequestData, request));
    }
}
