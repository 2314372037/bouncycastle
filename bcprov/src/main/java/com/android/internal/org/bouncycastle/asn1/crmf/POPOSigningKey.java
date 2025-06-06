package com.android.internal.org.bouncycastle.asn1.crmf;

import com.android.internal.org.bouncycastle.asn1.ASN1BitString;
import com.android.internal.org.bouncycastle.asn1.ASN1EncodableVector;
import com.android.internal.org.bouncycastle.asn1.ASN1Object;
import com.android.internal.org.bouncycastle.asn1.ASN1Primitive;
import com.android.internal.org.bouncycastle.asn1.ASN1Sequence;
import com.android.internal.org.bouncycastle.asn1.ASN1TaggedObject;
import com.android.internal.org.bouncycastle.asn1.ASN1Util;
import com.android.internal.org.bouncycastle.asn1.BERTags;
import com.android.internal.org.bouncycastle.asn1.DERSequence;
import com.android.internal.org.bouncycastle.asn1.DERTaggedObject;
import com.android.internal.org.bouncycastle.asn1.x509.AlgorithmIdentifier;

public class POPOSigningKey
    extends ASN1Object
{
    private POPOSigningKeyInput poposkInput;
    private AlgorithmIdentifier algorithmIdentifier;
    private ASN1BitString signature;

    private POPOSigningKey(ASN1Sequence seq)
    {
        int index = 0;

        if (seq.getObjectAt(index) instanceof ASN1TaggedObject)
        {
            ASN1TaggedObject tagObj = (ASN1TaggedObject)seq.getObjectAt(index++);

            poposkInput = POPOSigningKeyInput.getInstance(
                ASN1Util.getContextBaseUniversal(tagObj, 0, false, BERTags.SEQUENCE));
        }
        algorithmIdentifier = AlgorithmIdentifier.getInstance(seq.getObjectAt(index++));
        signature = ASN1BitString.getInstance(seq.getObjectAt(index));
    }

    public static POPOSigningKey getInstance(Object o)
    {
        if (o instanceof POPOSigningKey)
        {
            return (POPOSigningKey)o;
        }

        if (o != null)
        {
            return new POPOSigningKey(ASN1Sequence.getInstance(o));
        }

        return null;
    }

    public static POPOSigningKey getInstance(ASN1TaggedObject obj, boolean explicit)
    {
        return getInstance(ASN1Sequence.getInstance(obj, explicit));
    }

    /**
     * Creates a new Proof of Possession object for a signing key.
     *
     * @param poposkIn  the POPOSigningKeyInput structure, or null if the
     *                  CertTemplate includes both subject and publicKey values.
     * @param aid       the AlgorithmIdentifier used to sign the proof of possession.
     * @param signature a signature over the DER-encoded value of poposkIn,
     *                  or the DER-encoded value of certReq if poposkIn is null.
     */
    public POPOSigningKey(
        POPOSigningKeyInput poposkIn,
        AlgorithmIdentifier aid,
        ASN1BitString signature)
    {
        this.poposkInput = poposkIn;
        this.algorithmIdentifier = aid;
        this.signature = signature;
    }

    public POPOSigningKeyInput getPoposkInput()
    {
        return poposkInput;
    }

    public AlgorithmIdentifier getAlgorithmIdentifier()
    {
        return algorithmIdentifier;
    }

    public ASN1BitString getSignature()
    {
        return signature;
    }

    /**
     * <pre>
     * POPOSigningKey ::= SEQUENCE {
     *                      poposkInput           [0] POPOSigningKeyInput OPTIONAL,
     *                      algorithmIdentifier   AlgorithmIdentifier,
     *                      signature             BIT STRING }
     *  -- The signature (using "algorithmIdentifier") is on the
     *  -- DER-encoded value of poposkInput.  NOTE: If the CertReqMsg
     *  -- certReq CertTemplate contains the subject and publicKey values,
     *  -- then poposkInput MUST be omitted and the signature MUST be
     *  -- computed on the DER-encoded value of CertReqMsg certReq.  If
     *  -- the CertReqMsg certReq CertTemplate does not contain the public
     *  -- key and subject values, then poposkInput MUST be present and
     *  -- MUST be signed.  This strategy ensures that the public key is
     *  -- not present in both the poposkInput and CertReqMsg certReq
     *  -- CertTemplate fields.
     * </pre>
     *
     * @return a basic ASN.1 object representation.
     */
    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector v = new ASN1EncodableVector(3);

        if (poposkInput != null)
        {
            v.add(new DERTaggedObject(false, 0, poposkInput));
        }

        v.add(algorithmIdentifier);
        v.add(signature);

        return new DERSequence(v);
    }
}
