package com.android.internal.org.bouncycastle.cert.crmf;

import java.io.IOException;

import com.android.internal.org.bouncycastle.asn1.ASN1Integer;
import com.android.internal.org.bouncycastle.asn1.ASN1Object;
import com.android.internal.org.bouncycastle.asn1.ASN1ObjectIdentifier;
import com.android.internal.org.bouncycastle.asn1.ASN1Primitive;
import com.android.internal.org.bouncycastle.asn1.ASN1UTF8String;
import com.android.internal.org.bouncycastle.asn1.crmf.AttributeTypeAndValue;
import com.android.internal.org.bouncycastle.asn1.crmf.CRMFObjectIdentifiers;
import com.android.internal.org.bouncycastle.asn1.crmf.CertReqMsg;
import com.android.internal.org.bouncycastle.asn1.crmf.CertTemplate;
import com.android.internal.org.bouncycastle.asn1.crmf.Controls;
import com.android.internal.org.bouncycastle.asn1.crmf.PKIArchiveOptions;
import com.android.internal.org.bouncycastle.asn1.crmf.PKMACValue;
import com.android.internal.org.bouncycastle.asn1.crmf.POPOSigningKey;
import com.android.internal.org.bouncycastle.asn1.crmf.ProofOfPossession;
import com.android.internal.org.bouncycastle.cert.CertIOException;
import com.android.internal.org.bouncycastle.operator.ContentVerifier;
import com.android.internal.org.bouncycastle.operator.ContentVerifierProvider;
import com.android.internal.org.bouncycastle.operator.OperatorCreationException;
import com.android.internal.org.bouncycastle.util.Encodable;

/**
 * Carrier for a CRMF CertReqMsg.
 */
public class CertificateRequestMessage
    implements Encodable
{
    public static final int popRaVerified = ProofOfPossession.TYPE_RA_VERIFIED;
    public static final int popSigningKey = ProofOfPossession.TYPE_SIGNING_KEY;
    public static final int popKeyEncipherment = ProofOfPossession.TYPE_KEY_ENCIPHERMENT;
    public static final int popKeyAgreement = ProofOfPossession.TYPE_KEY_AGREEMENT;

    private final CertReqMsg certReqMsg;
    private final Controls controls;

    private static CertReqMsg parseBytes(byte[] encoding)
        throws IOException
    {
        try
        {
            return CertReqMsg.getInstance(encoding);
        }
        catch (ClassCastException e)
        {
            throw new CertIOException("malformed data: " + e.getMessage(), e);
        }
        catch (IllegalArgumentException e)
        {
            throw new CertIOException("malformed data: " + e.getMessage(), e);
        }
    }

    /**
     * Create a CertificateRequestMessage from the passed in bytes.
     *
     * @param certReqMsg BER/DER encoding of the CertReqMsg structure.
     * @throws IOException in the event of corrupted data, or an incorrect structure.
     */
    public CertificateRequestMessage(byte[] certReqMsg)
        throws IOException
    {
        this(parseBytes(certReqMsg));
    }

    public CertificateRequestMessage(CertReqMsg certReqMsg)
    {
        this.certReqMsg = certReqMsg;
        this.controls = certReqMsg.getCertReq().getControls();
    }

    /**
     * Return the underlying ASN.1 object defining this CertificateRequestMessage object.
     *
     * @return a CertReqMsg.
     */
    public CertReqMsg toASN1Structure()
    {
        return certReqMsg;
    }

    /**
     * Return the certificate request ID for this message.
     *
     * @return the certificate request ID.
     */
    public ASN1Integer getCertReqId()
    {
        return certReqMsg.getCertReq().getCertReqId();
    }

    /**
     * Return the certificate template contained in this message.
     *
     * @return  a CertTemplate structure.
     */
    public CertTemplate getCertTemplate()
    {
        return this.certReqMsg.getCertReq().getCertTemplate();
    }

    /**
     * Return whether or not this request has control values associated with it.
     *
     * @return true if there are control values present, false otherwise.
     */
    public boolean hasControls()
    {
        return controls != null;
    }

    /**
     * Return whether or not this request has a specific type of control value.
     *
     * @param type the type OID for the control value we are checking for.
     * @return true if a control value of type is present, false otherwise.
     */
    public boolean hasControl(ASN1ObjectIdentifier type)
    {
        return findControl(type) != null;
    }

    /**
     * Return a control value of the specified type.
     *
     * @param type the type OID for the control value we are checking for.
     * @return the control value if present, null otherwise.
     */
    public Control getControl(ASN1ObjectIdentifier type)
    {
        AttributeTypeAndValue found = findControl(type);

        if (found != null)
        {
            if (found.getType().equals(CRMFObjectIdentifiers.id_regCtrl_pkiArchiveOptions))
            {
                return new PKIArchiveControl(PKIArchiveOptions.getInstance(found.getValue()));
            }
            if (found.getType().equals(CRMFObjectIdentifiers.id_regCtrl_regToken))
            {
                return new RegTokenControl(ASN1UTF8String.getInstance(found.getValue()));
            }
            if (found.getType().equals(CRMFObjectIdentifiers.id_regCtrl_authenticator))
            {
                return new AuthenticatorControl(ASN1UTF8String.getInstance(found.getValue()));
            }
        }

        return null;
    }

    private AttributeTypeAndValue findControl(ASN1ObjectIdentifier type)
    {
        if (controls == null)
        {
            return null;
        }

        AttributeTypeAndValue[] tAndVs = controls.toAttributeTypeAndValueArray();
        AttributeTypeAndValue found = null;

        for (int i = 0; i != tAndVs.length; i++)
        {
            if (tAndVs[i].getType().equals(type))
            {
                found = tAndVs[i];
                break;
            }
        }

        return found;
    }

    /**
     * Return whether or not this request message has a proof-of-possession field in it.
     *
     * @return true if proof-of-possession is present, false otherwise.
     */
    public boolean hasProofOfPossession()
    {
        return this.certReqMsg.getPop() != null;
    }

    /**
     * Return the type of the proof-of-possession this request message provides.
     *
     * @return one of: popRaVerified, popSigningKey, popKeyEncipherment, popKeyAgreement
     */
    public int getProofOfPossessionType()
    {
        return this.certReqMsg.getPop().getType();
    }

    /**
     * Return whether or not the proof-of-possession (POP) is of the type popSigningKey and
     * it has a public key MAC associated with it.
     *
     * @return true if POP is popSigningKey and a PKMAC is present, false otherwise.
     */
    public boolean hasSigningKeyProofOfPossessionWithPKMAC()
    {
        ProofOfPossession pop = certReqMsg.getPop();

        if (pop.getType() != popSigningKey)
        {
            return false;
        }

        POPOSigningKey popoSign = POPOSigningKey.getInstance(pop.getObject());

        return popoSign.getPoposkInput().getPublicKeyMAC() != null;
    }

    /**
     * Return whether or not a signing key proof-of-possession (POP) is valid.
     *
     * @param verifierProvider a provider that can produce content verifiers for the signature contained in this POP.
     * @return true if the POP is valid, false otherwise.
     * @throws CRMFException if there is a problem in verification or content verifier creation.
     * @throws IllegalStateException if POP not appropriate.
     */
    public boolean isValidSigningKeyPOP(ContentVerifierProvider verifierProvider)
        throws CRMFException, IllegalStateException
    {
        ProofOfPossession pop = certReqMsg.getPop();

        if (pop.getType() != popSigningKey)
        {
            throw new IllegalStateException("not Signing Key type of proof of possession");
        }

        POPOSigningKey popoSign = POPOSigningKey.getInstance(pop.getObject());

        if (popoSign.getPoposkInput() != null && popoSign.getPoposkInput().getPublicKeyMAC() != null)
        {
            throw new IllegalStateException("verification requires password check");
        }

        return verifySignature(verifierProvider, popoSign);
    }

    /**
     * Return whether or not a signing key proof-of-possession (POP), with an associated PKMAC, is valid.
     *
     * @param verifierProvider a provider that can produce content verifiers for the signature contained in this POP.
     * @param macBuilder a suitable PKMACBuilder to create the MAC verifier.
     * @param password the password used to key the MAC calculation.
     * @return true if the POP is valid, false otherwise.
     * @throws CRMFException if there is a problem in verification or content verifier creation.
     * @throws IllegalStateException if POP not appropriate.
     */
    public boolean isValidSigningKeyPOP(ContentVerifierProvider verifierProvider, PKMACBuilder macBuilder, char[] password)
        throws CRMFException, IllegalStateException
    {
        ProofOfPossession pop = certReqMsg.getPop();

        if (pop.getType() != popSigningKey)
        {
            throw new IllegalStateException("not Signing Key type of proof of possession");
        }

        POPOSigningKey popoSign = POPOSigningKey.getInstance(pop.getObject());

        if (popoSign.getPoposkInput() == null || popoSign.getPoposkInput().getSender() != null)
        {
            throw new IllegalStateException("no PKMAC present in proof of possession");
        }

        PKMACValue pkMAC = popoSign.getPoposkInput().getPublicKeyMAC();
        PKMACValueVerifier macVerifier = new PKMACValueVerifier(macBuilder);

        return macVerifier.isValid(pkMAC, password, this.getCertTemplate().getPublicKey())
            && verifySignature(verifierProvider, popoSign);
    }

    private boolean verifySignature(ContentVerifierProvider verifierProvider, POPOSigningKey popoSign)
        throws CRMFException
    {
        ContentVerifier verifier;
        try
        {
            verifier = verifierProvider.get(popoSign.getAlgorithmIdentifier());
        }
        catch (OperatorCreationException e)
        {
            throw new CRMFException("unable to create verifier: " + e.getMessage(), e);
        }

        ASN1Object obj = popoSign.getPoposkInput();
        if (obj == null)
        {
            obj = certReqMsg.getCertReq();
        }

        CRMFUtil.derEncodeToStream(obj, verifier.getOutputStream());

        return verifier.verify(popoSign.getSignature().getOctets());
    }

    /**
     * Return the ASN.1 encoding of the certReqMsg we wrap.
     *
     * @return a byte array containing the binary encoding of the certReqMsg.
     * @throws IOException if there is an exception creating the encoding.
     */
    public byte[] getEncoded()
        throws IOException
    {
        return certReqMsg.getEncoded();
    }
}