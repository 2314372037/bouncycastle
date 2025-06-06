package com.android.internal.org.bouncycastle.jcajce.provider.asymmetric.elgamal;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.util.Enumeration;

import javax.crypto.interfaces.DHPrivateKey;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.DHPrivateKeySpec;

import com.android.internal.org.bouncycastle.asn1.ASN1Encodable;
import com.android.internal.org.bouncycastle.asn1.ASN1Encoding;
import com.android.internal.org.bouncycastle.asn1.ASN1Integer;
import com.android.internal.org.bouncycastle.asn1.ASN1ObjectIdentifier;
import com.android.internal.org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import com.android.internal.org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import com.android.internal.org.bouncycastle.crypto.params.ElGamalPrivateKeyParameters;
import com.android.internal.org.bouncycastle.internal.asn1.oiw.ElGamalParameter;
import com.android.internal.org.bouncycastle.internal.asn1.oiw.OIWObjectIdentifiers;
import com.android.internal.org.bouncycastle.jcajce.provider.asymmetric.util.PKCS12BagAttributeCarrierImpl;
import com.android.internal.org.bouncycastle.jce.interfaces.ElGamalPrivateKey;
import com.android.internal.org.bouncycastle.jce.interfaces.PKCS12BagAttributeCarrier;
import com.android.internal.org.bouncycastle.jce.spec.ElGamalParameterSpec;
import com.android.internal.org.bouncycastle.jce.spec.ElGamalPrivateKeySpec;

public class BCElGamalPrivateKey
    implements ElGamalPrivateKey, DHPrivateKey, PKCS12BagAttributeCarrier
{
    static final long serialVersionUID = 4819350091141529678L;
        
    private BigInteger      x;

    private transient ElGamalParameterSpec   elSpec;
    private transient PKCS12BagAttributeCarrierImpl attrCarrier = new PKCS12BagAttributeCarrierImpl();

    protected BCElGamalPrivateKey()
    {
    }

    BCElGamalPrivateKey(
        ElGamalPrivateKey key)
    {
        this.x = key.getX();
        this.elSpec = key.getParameters();
    }

    BCElGamalPrivateKey(
        DHPrivateKey key)
    {
        this.x = key.getX();
        this.elSpec = new ElGamalParameterSpec(key.getParams().getP(), key.getParams().getG());
    }
    
    BCElGamalPrivateKey(
        ElGamalPrivateKeySpec spec)
    {
        this.x = spec.getX();
        this.elSpec = new ElGamalParameterSpec(spec.getParams().getP(), spec.getParams().getG());
    }

    BCElGamalPrivateKey(
        DHPrivateKeySpec spec)
    {
        this.x = spec.getX();
        this.elSpec = new ElGamalParameterSpec(spec.getP(), spec.getG());
    }
    
    BCElGamalPrivateKey(
        PrivateKeyInfo info)
        throws IOException
    {
        ElGamalParameter     params = ElGamalParameter.getInstance(info.getPrivateKeyAlgorithm().getParameters());
        ASN1Integer      derX = ASN1Integer.getInstance(info.parsePrivateKey());

        this.x = derX.getValue();
        this.elSpec = new ElGamalParameterSpec(params.getP(), params.getG());
    }

    BCElGamalPrivateKey(
        ElGamalPrivateKeyParameters params)
    {
        this.x = params.getX();
        this.elSpec = new ElGamalParameterSpec(params.getParameters().getP(), params.getParameters().getG());
    }

    public String getAlgorithm()
    {
        return "ElGamal";
    }

    /**
     * return the encoding format we produce in getEncoded().
     *
     * @return the string "PKCS#8"
     */
    public String getFormat()
    {
        return "PKCS#8";
    }

    /**
     * Return a PKCS8 representation of the key. The sequence returned
     * represents a full PrivateKeyInfo object.
     *
     * @return a PKCS8 representation of the key.
     */
    public byte[] getEncoded()
    {
        try
        {
            PrivateKeyInfo          info = new PrivateKeyInfo(new AlgorithmIdentifier(OIWObjectIdentifiers.elGamalAlgorithm, new ElGamalParameter(elSpec.getP(), elSpec.getG())), new ASN1Integer(getX()));

            return info.getEncoded(ASN1Encoding.DER);
        }
        catch (IOException e)
        {
            return null;
        }
    }

    public ElGamalParameterSpec getParameters()
    {
        return elSpec;
    }

    public DHParameterSpec getParams()
    {
        return new DHParameterSpec(elSpec.getP(), elSpec.getG());
    }
    
    public BigInteger getX()
    {
        return x;
    }

    public boolean equals(
        Object o)
    {
        if (!(o instanceof DHPrivateKey))
        {
            return false;
        }

        DHPrivateKey other = (DHPrivateKey)o;

        return this.getX().equals(other.getX())
            && this.getParams().getG().equals(other.getParams().getG())
            && this.getParams().getP().equals(other.getParams().getP())
            && this.getParams().getL() == other.getParams().getL();
    }

    public int hashCode()
    {
        return this.getX().hashCode() ^ this.getParams().getG().hashCode()
                ^ this.getParams().getP().hashCode() ^ this.getParams().getL();
    }

    private void readObject(
        ObjectInputStream   in)
        throws IOException, ClassNotFoundException
    {
        in.defaultReadObject();

        this.elSpec = new ElGamalParameterSpec((BigInteger)in.readObject(), (BigInteger)in.readObject());
        this.attrCarrier = new PKCS12BagAttributeCarrierImpl();
    }

    private void writeObject(
        ObjectOutputStream  out)
        throws IOException
    {
        out.defaultWriteObject();

        out.writeObject(elSpec.getP());
        out.writeObject(elSpec.getG());
    }

    public void setBagAttribute(
        ASN1ObjectIdentifier oid,
        ASN1Encodable attribute)
    {
        attrCarrier.setBagAttribute(oid, attribute);
    }

    public ASN1Encodable getBagAttribute(
        ASN1ObjectIdentifier oid)
    {
        return attrCarrier.getBagAttribute(oid);
    }

    public Enumeration getBagAttributeKeys()
    {
        return attrCarrier.getBagAttributeKeys();
    }
}
