package com.android.internal.org.bouncycastle.asn1.x509;

import com.android.internal.org.bouncycastle.asn1.ASN1Object;
import com.android.internal.org.bouncycastle.asn1.ASN1ObjectIdentifier;
import com.android.internal.org.bouncycastle.asn1.ASN1Primitive;
import com.android.internal.org.bouncycastle.asn1.ASN1Sequence;
import com.android.internal.org.bouncycastle.asn1.ASN1TaggedObject;
import com.android.internal.org.bouncycastle.asn1.DERSequence;

public class CertificatePolicies
    extends ASN1Object
{
    private final PolicyInformation[] policyInformation;

    private static PolicyInformation[] copy(PolicyInformation[] policyInfo)
    {
        PolicyInformation[] result = new PolicyInformation[policyInfo.length];
        System.arraycopy(policyInfo, 0, result, 0, policyInfo.length);
        return result;
    }

    public static CertificatePolicies getInstance(
        Object  obj)
    {
        if (obj instanceof CertificatePolicies)
        {
            return (CertificatePolicies)obj;
        }

        if (obj != null)
        {
            return new CertificatePolicies(ASN1Sequence.getInstance(obj));
        }

        return null;
    }

    public static CertificatePolicies getInstance(
        ASN1TaggedObject obj,
        boolean          explicit)
    {
        return getInstance(ASN1Sequence.getInstance(obj, explicit));
    }

    /**
     * Retrieve a CertificatePolicies for a passed in Extensions object, if present.
     *
     * @param extensions the extensions object to be examined.
     * @return  the CertificatePolicies, null if the extension is not present.
     */
    public static CertificatePolicies fromExtensions(Extensions extensions)
    {
        return getInstance(Extensions.getExtensionParsedValue(extensions, Extension.certificatePolicies));
    }

    /**
     * Construct a CertificatePolicies object containing one PolicyInformation.
     * 
     * @param name the name to be contained.
     */
    public CertificatePolicies(
        PolicyInformation  name)
    {
        this.policyInformation = new PolicyInformation[] { name };
    }

    public CertificatePolicies(
        PolicyInformation[] policyInformation)
    {
        this.policyInformation = copy(policyInformation);
    }

    private CertificatePolicies(
        ASN1Sequence  seq)
    {
        this.policyInformation = new PolicyInformation[seq.size()];

        for (int i = 0; i != seq.size(); i++)
        {
            policyInformation[i] = PolicyInformation.getInstance(seq.getObjectAt(i));
        }
    }

    public PolicyInformation[] getPolicyInformation()
    {
        return copy(policyInformation);
    }

    public PolicyInformation getPolicyInformation(ASN1ObjectIdentifier policyIdentifier)
    {
        for (int i = 0; i != policyInformation.length; i++)
        {
            if (policyIdentifier.equals(policyInformation[i].getPolicyIdentifier()))
            {
                 return policyInformation[i];
            }
        }

        return null;
    }

    /**
     * Produce an object suitable for an ASN1OutputStream.
     * <pre>
     * CertificatePolicies ::= SEQUENCE SIZE {1..MAX} OF PolicyInformation
     * </pre>
     */
    public ASN1Primitive toASN1Primitive()
    {
        return new DERSequence(policyInformation);
    }

    public String toString()
    {
        StringBuffer p = new StringBuffer();
        for (int i = 0; i < policyInformation.length; i++)
        {
            if (p.length() != 0)
            {
                p.append(", ");
            }
            p.append(policyInformation[i]);
        }

        return "CertificatePolicies: [" + p + "]";
    }
}
