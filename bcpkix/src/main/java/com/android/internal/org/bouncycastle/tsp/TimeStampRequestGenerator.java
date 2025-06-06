package com.android.internal.org.bouncycastle.tsp;

import java.io.IOException;
import java.math.BigInteger;

import com.android.internal.org.bouncycastle.asn1.ASN1Boolean;
import com.android.internal.org.bouncycastle.asn1.ASN1Encodable;
import com.android.internal.org.bouncycastle.asn1.ASN1Integer;
import com.android.internal.org.bouncycastle.asn1.ASN1ObjectIdentifier;
import com.android.internal.org.bouncycastle.asn1.tsp.MessageImprint;
import com.android.internal.org.bouncycastle.asn1.tsp.TimeStampReq;
import com.android.internal.org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import com.android.internal.org.bouncycastle.asn1.x509.Extensions;
import com.android.internal.org.bouncycastle.asn1.x509.ExtensionsGenerator;
import com.android.internal.org.bouncycastle.operator.DefaultDigestAlgorithmIdentifierFinder;

/**
 * Generator for RFC 3161 Time Stamp Request objects.
 */
public class TimeStampRequestGenerator
{
    private static final DefaultDigestAlgorithmIdentifierFinder dgstAlgFinder = new DefaultDigestAlgorithmIdentifierFinder();

    private ASN1ObjectIdentifier reqPolicy;

    private ASN1Boolean certReq;
    private ExtensionsGenerator extGenerator = new ExtensionsGenerator();

    public TimeStampRequestGenerator()
    {
    }

    /**
     * @deprecated use method taking ASN1ObjectIdentifier
     * @param reqPolicy
     */
    public void setReqPolicy(
        String reqPolicy)
    {
        this.reqPolicy= new ASN1ObjectIdentifier(reqPolicy);
    }

    public void setReqPolicy(
        ASN1ObjectIdentifier reqPolicy)
    {
        this.reqPolicy= reqPolicy;
    }

    public void setCertReq(
        boolean certReq)
    {
        this.certReq = ASN1Boolean.getInstance(certReq);
    }

    /**
     * add a given extension field for the standard extensions tag (tag 3)
     * @throws IOException
     * @deprecated use method taking ASN1ObjectIdentifier
     */
    public void addExtension(
        String          OID,
        boolean         critical,
        ASN1Encodable   value)
        throws IOException
    {
        this.addExtension(OID, critical, value.toASN1Primitive().getEncoded());
    }

    /**
     * add a given extension field for the standard extensions tag
     * The value parameter becomes the contents of the octet string associated
     * with the extension.
     * @deprecated use method taking ASN1ObjectIdentifier
     */
    public void addExtension(
        String          OID,
        boolean         critical,
        byte[]          value)
    {
        extGenerator.addExtension(new ASN1ObjectIdentifier(OID), critical, value);
    }

    /**
     * add a given extension field for the standard extensions tag (tag 3)
     * @throws TSPIOException
     */
    public void addExtension(
        ASN1ObjectIdentifier oid,
        boolean              isCritical,
        ASN1Encodable        value)
        throws TSPIOException
    {
        TSPUtil.addExtension(extGenerator, oid, isCritical, value);
    }

    /**
     * add a given extension field for the standard extensions tag
     * The value parameter becomes the contents of the octet string associated
     * with the extension.
     */
    public void addExtension(
        ASN1ObjectIdentifier oid,
        boolean              isCritical,
        byte[]               value)
    {
        extGenerator.addExtension(oid, isCritical, value);
    }

    /**
     * @deprecated use method taking ANS1ObjectIdentifier
     */
    public TimeStampRequest generate(
        String digestAlgorithm,
        byte[] digest)
    {
        return this.generate(digestAlgorithm, digest, null);
    }

    /**
     * @deprecated use method taking ANS1ObjectIdentifier
     */
    public TimeStampRequest generate(
        String      digestAlgorithmOID,
        byte[]      digest,
        BigInteger  nonce)
    {
        if (digestAlgorithmOID == null)
        {
            throw new IllegalArgumentException("No digest algorithm specified");
        }

        ASN1ObjectIdentifier digestAlgOID = new ASN1ObjectIdentifier(digestAlgorithmOID);

        AlgorithmIdentifier algID = dgstAlgFinder.find(digestAlgOID);
        MessageImprint messageImprint = new MessageImprint(algID, digest);

        Extensions  ext = null;
        
        if (!extGenerator.isEmpty())
        {
            ext = extGenerator.generate();
        }
        
        if (nonce != null)
        {
            return new TimeStampRequest(new TimeStampReq(messageImprint,
                    reqPolicy, new ASN1Integer(nonce), certReq, ext));
        }
        else
        {
            return new TimeStampRequest(new TimeStampReq(messageImprint,
                    reqPolicy, null, certReq, ext));
        }
    }

    public TimeStampRequest generate(ASN1ObjectIdentifier digestAlgorithm, byte[] digest)
    {
        return generate(dgstAlgFinder.find(digestAlgorithm), digest);
    }

    public TimeStampRequest generate(ASN1ObjectIdentifier digestAlgorithm, byte[] digest, BigInteger nonce)
    {
        return generate(dgstAlgFinder.find(digestAlgorithm), digest, nonce);
    }

    public TimeStampRequest generate(
        AlgorithmIdentifier     digestAlgorithmID,
        byte[]                  digest)
    {
        return generate(digestAlgorithmID, digest, null);
    }

    public TimeStampRequest generate(
        AlgorithmIdentifier     digestAlgorithmID,
        byte[]                  digest,
        BigInteger              nonce)
    {
        if (digestAlgorithmID == null)
        {
            throw new IllegalArgumentException("digest algorithm not specified");
        }

        MessageImprint messageImprint = new MessageImprint(digestAlgorithmID, digest);

        Extensions  ext = null;

        if (!extGenerator.isEmpty())
        {
            ext = extGenerator.generate();
        }

        if (nonce != null)
        {
            return new TimeStampRequest(new TimeStampReq(messageImprint,
                    reqPolicy, new ASN1Integer(nonce), certReq, ext));
        }
        else
        {
            return new TimeStampRequest(new TimeStampReq(messageImprint,
                    reqPolicy, null, certReq, ext));
        }
    }
}
