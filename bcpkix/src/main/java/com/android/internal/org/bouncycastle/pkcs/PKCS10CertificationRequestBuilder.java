package com.android.internal.org.bouncycastle.pkcs;

import java.io.IOException;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

import com.android.internal.org.bouncycastle.asn1.ASN1Encodable;
import com.android.internal.org.bouncycastle.asn1.ASN1EncodableVector;
import com.android.internal.org.bouncycastle.asn1.ASN1Encoding;
import com.android.internal.org.bouncycastle.asn1.ASN1ObjectIdentifier;
import com.android.internal.org.bouncycastle.asn1.DERBitString;
import com.android.internal.org.bouncycastle.asn1.DERSet;
import com.android.internal.org.bouncycastle.asn1.pkcs.Attribute;
import com.android.internal.org.bouncycastle.asn1.pkcs.CertificationRequest;
import com.android.internal.org.bouncycastle.asn1.pkcs.CertificationRequestInfo;
import com.android.internal.org.bouncycastle.asn1.x500.X500Name;
import com.android.internal.org.bouncycastle.asn1.x509.Extension;
import com.android.internal.org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import com.android.internal.org.bouncycastle.operator.ContentSigner;

/**
 * A class for creating PKCS#10 Certification requests.
 * <pre>
 * CertificationRequest ::= SEQUENCE {
 *   certificationRequestInfo  CertificationRequestInfo,
 *   signatureAlgorithm        AlgorithmIdentifier{{ SignatureAlgorithms }},
 *   signature                 BIT STRING
 * }
 *
 * CertificationRequestInfo ::= SEQUENCE {
 *   version             INTEGER { v1(0) } (v1,...),
 *   subject             Name,
 *   subjectPKInfo   SubjectPublicKeyInfo{{ PKInfoAlgorithms }},
 *   attributes          [0] Attributes{{ CRIAttributes }}
 *  }
 *
 *  Attributes { ATTRIBUTE:IOSet } ::= SET OF Attribute{{ IOSet }}
 *
 *  Attribute { ATTRIBUTE:IOSet } ::= SEQUENCE {
 *    type    ATTRIBUTE.&amp;id({IOSet}),
 *    values  SET SIZE(1..MAX) OF ATTRIBUTE.&amp;Type({IOSet}{\@type})
 *  }
 * </pre>
 */
public class PKCS10CertificationRequestBuilder
{
    private SubjectPublicKeyInfo publicKeyInfo;
    private X500Name subject;
    private List attributes = new ArrayList();
    private boolean leaveOffEmpty = false;


    public PKCS10CertificationRequestBuilder(PKCS10CertificationRequestBuilder original)
    {
        this.publicKeyInfo = original.publicKeyInfo;
        this.subject = original.subject;
        this.leaveOffEmpty = original.leaveOffEmpty;
        this.attributes = new ArrayList(original.attributes);
    }


    /**
     * Basic constructor.
     *
     * @param subject       the X.500 Name defining the certificate subject this request is for.
     * @param publicKeyInfo the info structure for the public key to be associated with this subject.
     */
    public PKCS10CertificationRequestBuilder(X500Name subject, SubjectPublicKeyInfo publicKeyInfo)
    {
        this.subject = subject;
        this.publicKeyInfo = publicKeyInfo;
    }

    /**
     * Set an attribute to the certification request we are building.
     * Removed existing attributes with the same attrType.
     *
     * @param attrType  the OID giving the type of the attribute.
     * @param attrValue the ASN.1 structure that forms the value of the attribute.
     * @return this builder object.
     */
    public PKCS10CertificationRequestBuilder setAttribute(ASN1ObjectIdentifier attrType, ASN1Encodable attrValue)
    {
        // Remove existing copies of the attribute.
        for (Iterator it = attributes.iterator(); it.hasNext(); )
        {
            if (((Attribute)it.next()).getAttrType().equals(attrType))
            {
                throw new IllegalStateException("Attribute " + attrType.toString() + " is already set");
            }
        }
        addAttribute(attrType, attrValue);
        return this;
    }

    /**
     * Add an attribute with multiple values to the certification request we are building.
     * Removed existing attributes with the same attrType.
     *
     * @param attrType  the OID giving the type of the attribute.
     * @param attrValue the ASN.1 structure that forms the value of the attribute.
     * @return this builder object.
     */
    public PKCS10CertificationRequestBuilder setAttribute(ASN1ObjectIdentifier attrType, ASN1Encodable[] attrValue)
    {
        // Remove existing copies of the attribute.
        for (Iterator it = attributes.iterator(); it.hasNext(); )
        {
            if (((Attribute)it.next()).getAttrType().equals(attrType))
            {
                throw new IllegalStateException("Attribute " + attrType.toString() + " is already set");
            }
        }
        addAttribute(attrType, attrValue);
        return this;
    }


    /**
     * Add an attribute to the certification request we are building.
     *
     * @param attrType  the OID giving the type of the attribute.
     * @param attrValue the ASN.1 structure that forms the value of the attribute.
     * @return this builder object.
     */
    public PKCS10CertificationRequestBuilder addAttribute(ASN1ObjectIdentifier attrType, ASN1Encodable attrValue)
    {
        attributes.add(new Attribute(attrType, new DERSet(attrValue)));
        return this;
    }

    /**
     * Add an attribute with multiple values to the certification request we are building.
     *
     * @param attrType   the OID giving the type of the attribute.
     * @param attrValues an array of ASN.1 structures that form the value of the attribute.
     * @return this builder object.
     */
    public PKCS10CertificationRequestBuilder addAttribute(ASN1ObjectIdentifier attrType, ASN1Encodable[] attrValues)
    {
        attributes.add(new Attribute(attrType, new DERSet(attrValues)));
        return this;
    }

    /**
     * The attributes field in PKCS10 should encoded to an empty tagged set if there are
     * no attributes. Some CAs will reject requests with the attribute field present.
     *
     * @param leaveOffEmpty true if empty attributes should be left out of the encoding false otherwise.
     * @return this builder object.
     */
    public PKCS10CertificationRequestBuilder setLeaveOffEmptyAttributes(boolean leaveOffEmpty)
    {
        this.leaveOffEmpty = leaveOffEmpty;

        return this;
    }

    /**
     * Generate an PKCS#10 request based on the past in signer.
     *
     * @param signer the content signer to be used to generate the signature validating the certification request.
     * @return a holder containing the resulting PKCS#10 certification request.
     */
    public PKCS10CertificationRequest build(
        ContentSigner signer)
    {
        CertificationRequestInfo info;

        if (attributes.isEmpty())
        {
            if (leaveOffEmpty)
            {
                info = new CertificationRequestInfo(subject, publicKeyInfo, null);
            }
            else
            {
                info = new CertificationRequestInfo(subject, publicKeyInfo, new DERSet());
            }
        }
        else
        {
            ASN1EncodableVector v = new ASN1EncodableVector();

            for (Iterator it = attributes.iterator(); it.hasNext(); )
            {
                v.add(Attribute.getInstance(it.next()));
            }

            info = new CertificationRequestInfo(subject, publicKeyInfo, new DERSet(v));
        }

        try
        {
            OutputStream sOut = signer.getOutputStream();

            sOut.write(info.getEncoded(ASN1Encoding.DER));

            sOut.close();

            return new PKCS10CertificationRequest(new CertificationRequest(info, signer.getAlgorithmIdentifier(), new DERBitString(signer.getSignature())));
        }
        catch (IOException e)
        {
            throw new IllegalStateException("cannot produce certification request signature");
        }
    }

    /**
     * Generate a PKCS10 certificate request, based on the current issuer and subject
     * using the passed in signer and containing altSignatureAlgorithm. altSubjectPublicKeyInfo, and altSignatureValue attributes
     * based on the passed altSigner.
     *
     * @param signer    the content signer to be used to generate the signature validating the certification request.
     * @param altPublicKey the public key to verify the altSignatureValue generated as part of this build.
     * @param altSigner the content signer used to create the altSignatureAlgorithm and altSignatureValue extension.
     * @return a holder containing the resulting signed certificate.
     */
    public PKCS10CertificationRequest build(
        ContentSigner signer,
        SubjectPublicKeyInfo altPublicKey,
        ContentSigner altSigner)
    {
        CertificationRequestInfo info;

        ASN1EncodableVector v = new ASN1EncodableVector();

        for (Iterator it = attributes.iterator(); it.hasNext(); )
        {
            v.add(Attribute.getInstance(it.next()));
        }

        v.add(new Attribute(Extension.subjectAltPublicKeyInfo, new DERSet(altPublicKey)));
        v.add(new Attribute(Extension.altSignatureAlgorithm, new DERSet(altSigner.getAlgorithmIdentifier())));

        info = new CertificationRequestInfo(subject, publicKeyInfo, new DERSet(v));

        // add altSignatureValue
        try
        {
            OutputStream sOut = altSigner.getOutputStream();

            sOut.write(info.getEncoded(ASN1Encoding.DER));

            sOut.close();

            v.add(new Attribute(Extension.altSignatureValue, new DERSet(new DERBitString(altSigner.getSignature()))));

            info = new CertificationRequestInfo(subject, publicKeyInfo, new DERSet(v));
        }
        catch (IOException e)
        {
            throw new IllegalStateException("cannot produce certification request signature");
        }

        // create final request
        try
        {
            OutputStream sOut = signer.getOutputStream();

            sOut.write(info.getEncoded(ASN1Encoding.DER));

            sOut.close();

            return new PKCS10CertificationRequest(new CertificationRequest(info, signer.getAlgorithmIdentifier(), new DERBitString(signer.getSignature())));
        }
        catch (IOException e)
        {
            throw new IllegalStateException("cannot produce certification request signature");
        }
    }
}
