package com.android.internal.org.bouncycastle.its.bc;

import java.io.IOException;
import java.io.OutputStream;

import com.android.internal.org.bouncycastle.asn1.ASN1ObjectIdentifier;
import com.android.internal.org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import com.android.internal.org.bouncycastle.asn1.sec.SECObjectIdentifiers;
import com.android.internal.org.bouncycastle.asn1.teletrust.TeleTrusTObjectIdentifiers;
import com.android.internal.org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import com.android.internal.org.bouncycastle.crypto.Digest;
import com.android.internal.org.bouncycastle.crypto.io.DigestOutputStream;
import com.android.internal.org.bouncycastle.crypto.params.ECNamedDomainParameters;
import com.android.internal.org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import com.android.internal.org.bouncycastle.crypto.signers.DSADigestSigner;
import com.android.internal.org.bouncycastle.crypto.signers.ECDSASigner;
import com.android.internal.org.bouncycastle.its.ITSCertificate;
import com.android.internal.org.bouncycastle.its.operator.ITSContentSigner;
import com.android.internal.org.bouncycastle.operator.OperatorCreationException;
import com.android.internal.org.bouncycastle.operator.bc.BcDefaultDigestProvider;
import com.android.internal.org.bouncycastle.util.Arrays;

public class BcITSContentSigner
    implements ITSContentSigner
{
    private final ECPrivateKeyParameters privKey;
    private final ITSCertificate signerCert;
    private final AlgorithmIdentifier digestAlgo;
    private final Digest digest;
    private final byte[] parentData;
    private final ASN1ObjectIdentifier curveID;
    private final byte[] parentDigest;

    /**
     * Constructor for self-signing.
     *
     * @param privKey
     */
    public BcITSContentSigner(ECPrivateKeyParameters privKey)
    {
        this(privKey, null);
    }

    public BcITSContentSigner(ECPrivateKeyParameters privKey, ITSCertificate signerCert)
    {
        this.privKey = privKey;
        this.curveID = ((ECNamedDomainParameters)privKey.getParameters()).getName();
        this.signerCert = signerCert;
        if (curveID.equals(SECObjectIdentifiers.secp256r1))
        {
            digestAlgo = new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha256);
        }
        else if (curveID.equals(TeleTrusTObjectIdentifiers.brainpoolP256r1))
        {
            digestAlgo = new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha256);
        }
        else if (curveID.equals(TeleTrusTObjectIdentifiers.brainpoolP384r1))
        {
            digestAlgo = new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha384);
        }
        else
        {
            throw new IllegalArgumentException("unknown key type");
        }

        try
        {
            this.digest = BcDefaultDigestProvider.INSTANCE.get(digestAlgo);
        }
        catch (OperatorCreationException e)
        {
            throw new IllegalStateException("cannot recognise digest type: " + digestAlgo.getAlgorithm());
        }

        if (signerCert != null)
        {
            try
            {
                this.parentData = signerCert.getEncoded();
                this.parentDigest = new byte[digest.getDigestSize()];

                digest.update(parentData, 0, parentData.length);

                digest.doFinal(parentDigest, 0);
            }
            catch (IOException e)
            {
                throw new IllegalStateException("signer certificate encoding failed: " + e.getMessage());
            }
        }
        else
        {
            // self signed so we use a null digest for the parent.
            this.parentData = null;
            this.parentDigest = new byte[digest.getDigestSize()];
            digest.doFinal(parentDigest, 0);
        }
    }

    public ITSCertificate getAssociatedCertificate()
    {
        return signerCert;
    }

    public byte[] getAssociatedCertificateDigest()
    {
        return Arrays.clone(parentDigest);
    }

    public AlgorithmIdentifier getDigestAlgorithm()
    {
        return digestAlgo;
    }

    public OutputStream getOutputStream()
    {
        return new DigestOutputStream(digest);
    }

    public boolean isForSelfSigning()
    {
        return parentData == null;
    }

    public ASN1ObjectIdentifier getCurveID()
    {
        return curveID;
    }

    public byte[] getSignature()
    {
        byte[] clientCertDigest = new byte[digest.getDigestSize()];

        digest.doFinal(clientCertDigest, 0);

        final DSADigestSigner signer = new DSADigestSigner(new ECDSASigner(), digest);

        signer.init(true, privKey);

        signer.update(clientCertDigest, 0, clientCertDigest.length);

        signer.update(parentDigest, 0, parentDigest.length);

        return signer.generateSignature();
    }
}
