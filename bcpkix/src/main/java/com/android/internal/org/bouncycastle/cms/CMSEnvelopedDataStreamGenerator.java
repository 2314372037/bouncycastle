package com.android.internal.org.bouncycastle.cms;

import java.io.IOException;
import java.io.OutputStream;
import java.util.Collections;

import com.android.internal.org.bouncycastle.asn1.ASN1EncodableVector;
import com.android.internal.org.bouncycastle.asn1.ASN1Integer;
import com.android.internal.org.bouncycastle.asn1.ASN1ObjectIdentifier;
import com.android.internal.org.bouncycastle.asn1.BERSequenceGenerator;
import com.android.internal.org.bouncycastle.asn1.DLSet;
import com.android.internal.org.bouncycastle.asn1.cms.CMSObjectIdentifiers;
import com.android.internal.org.bouncycastle.asn1.cms.EnvelopedData;
import com.android.internal.org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import com.android.internal.org.bouncycastle.operator.OutputAEADEncryptor;
import com.android.internal.org.bouncycastle.operator.OutputEncryptor;

/**
 * General class for generating a CMS enveloped-data message stream.
 * <p>
 * A simple example of usage.
 * <pre>
 *      CMSEnvelopedDataStreamGenerator edGen = new CMSEnvelopedDataStreamGenerator();
 *
 *      edGen.addRecipientInfoGenerator(new JceKeyTransRecipientInfoGenerator(recipientCert).setProvider("BC"));
 *
 *      ByteArrayOutputStream  bOut = new ByteArrayOutputStream();
 *
 *      OutputStream out = edGen.open(
 *                              bOut, new JceCMSContentEncryptorBuilder(CMSAlgorithm.DES_EDE3_CBC)
 *                                              .setProvider("BC").build());
 *      out.write(data);
 *
 *      out.close();
 * </pre>
 */
public class CMSEnvelopedDataStreamGenerator
    extends CMSEnvelopedGenerator
{
    private int                 _bufferSize;
    private boolean             _berEncodeRecipientSet;

    /**
     * base constructor
     */
    public CMSEnvelopedDataStreamGenerator()
    {
    }

    /**
     * Set the underlying string size for encapsulated data
     *
     * @param bufferSize length of octet strings to buffer the data.
     */
    public void setBufferSize(
        int bufferSize)
    {
        _bufferSize = bufferSize;
    }

    /**
     * Use a BER Set to store the recipient information
     */
    public void setBEREncodeRecipients(
        boolean berEncodeRecipientSet)
    {
        _berEncodeRecipientSet = berEncodeRecipientSet;
    }

    private ASN1Integer getVersion(ASN1EncodableVector recipientInfos)
    {
        if (unprotectedAttributeGenerator != null)
        {
            // mark unprotected attributes as non-null.
            return new ASN1Integer(EnvelopedData.calculateVersion(originatorInfo, new DLSet(recipientInfos), new DLSet()));
        }
        return new ASN1Integer(EnvelopedData.calculateVersion(originatorInfo, new DLSet(recipientInfos), null));
    }

    private OutputStream doOpen(
        ASN1ObjectIdentifier dataType,
        OutputStream         out,
        OutputEncryptor      encryptor)
        throws IOException, CMSException
    {
        ASN1EncodableVector recipientInfos = CMSUtils.getRecipentInfos(encryptor.getKey(), recipientInfoGenerators);

        return open(dataType, out, recipientInfos, encryptor);
    }

    protected OutputStream open(
        ASN1ObjectIdentifier dataType,
        OutputStream         out,
        ASN1EncodableVector  recipientInfos,
        OutputEncryptor      encryptor)
        throws IOException
    {
        //
        // ContentInfo
        //
        BERSequenceGenerator cGen = new BERSequenceGenerator(out);

        cGen.addObject(CMSObjectIdentifiers.envelopedData);

        //
        // Encrypted Data
        //
        BERSequenceGenerator envGen = new BERSequenceGenerator(cGen.getRawOutputStream(), 0, true);

        envGen.addObject(getVersion(recipientInfos));

        CMSUtils.addOriginatorInfoToGenerator(envGen, originatorInfo);

        CMSUtils.addRecipientInfosToGenerator(recipientInfos, envGen, _berEncodeRecipientSet);

        BERSequenceGenerator eiGen = new BERSequenceGenerator(envGen.getRawOutputStream());

        eiGen.addObject(dataType);

        AlgorithmIdentifier encAlgId = encryptor.getAlgorithmIdentifier();

        eiGen.getRawOutputStream().write(encAlgId.getEncoded());

        OutputStream octetStream = CMSUtils.createBEROctetOutputStream(
            eiGen.getRawOutputStream(), 0, false, _bufferSize);

        return new CmsEnvelopedDataOutputStream(encryptor, octetStream, cGen, envGen, eiGen);
    }

    protected OutputStream open(
        OutputStream        out,
        ASN1EncodableVector recipientInfos,
        OutputEncryptor     encryptor)
        throws CMSException
    {
        try
        {
            return open(CMSObjectIdentifiers.data, out, recipientInfos, encryptor);
        }
        catch (IOException e)
        {
            throw new CMSException("exception decoding algorithm parameters.", e);
        }
    }

    /**
     * generate an enveloped object that contains an CMS Enveloped Data
     * object using the given encryptor.
     */
    public OutputStream open(
        OutputStream    out,
        OutputEncryptor encryptor)
        throws CMSException, IOException
    {
        return doOpen(new ASN1ObjectIdentifier(CMSObjectIdentifiers.data.getId()), out, encryptor);
    }

    /**
     * generate an enveloped object that contains an CMS Enveloped Data
     * object using the given encryptor and marking the data as being of the passed
     * in type.
     */
    public OutputStream open(
        ASN1ObjectIdentifier dataType,
        OutputStream         out,
        OutputEncryptor      encryptor)
        throws CMSException, IOException
    {
        return doOpen(dataType, out, encryptor);
    }

    private class CmsEnvelopedDataOutputStream
        extends OutputStream
    {
        private final OutputEncryptor _encryptor;
        private final OutputStream _cOut;
        private OutputStream _octetStream;
        private BERSequenceGenerator _cGen;
        private BERSequenceGenerator _envGen;
        private BERSequenceGenerator _eiGen;

        public CmsEnvelopedDataOutputStream(
            OutputEncryptor encryptor,
            OutputStream   octetStream,
            BERSequenceGenerator cGen,
            BERSequenceGenerator envGen,
            BERSequenceGenerator eiGen)
        {
            _encryptor = encryptor;
            _octetStream = octetStream;
            _cOut = encryptor.getOutputStream(octetStream);
            _cGen = cGen;
            _envGen = envGen;
            _eiGen = eiGen;
        }

        public void write(
            int b)
            throws IOException
        {
            _cOut.write(b);
        }

        public void write(
            byte[] bytes,
            int    off,
            int    len)
            throws IOException
        {
            _cOut.write(bytes, off, len);
        }

        public void write(
            byte[] bytes)
            throws IOException
        {
            _cOut.write(bytes);
        }

        public void close()
            throws IOException
        {
            _cOut.close();
            if (_encryptor instanceof OutputAEADEncryptor)
            {
                // enveloped data so MAC appended to cipher text.
                _octetStream.write(((OutputAEADEncryptor)_encryptor).getMAC());
                _octetStream.close();
            }
            _eiGen.close();

            CMSUtils.addAttriSetToGenerator(_envGen, unprotectedAttributeGenerator, 1, Collections.EMPTY_MAP);

            _envGen.close();
            _cGen.close();
        }
    }
}
