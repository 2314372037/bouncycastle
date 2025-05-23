package com.android.internal.org.bouncycastle.pqc.jcajce.provider.falcon;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;

import com.android.internal.org.bouncycastle.asn1.ASN1Set;
import com.android.internal.org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import com.android.internal.org.bouncycastle.pqc.crypto.crystals.dilithium.DilithiumPrivateKeyParameters;
import com.android.internal.org.bouncycastle.pqc.crypto.falcon.FalconPrivateKeyParameters;
import com.android.internal.org.bouncycastle.pqc.crypto.falcon.FalconPublicKeyParameters;
import com.android.internal.org.bouncycastle.pqc.crypto.util.PrivateKeyFactory;
import com.android.internal.org.bouncycastle.pqc.crypto.util.PrivateKeyInfoFactory;
import com.android.internal.org.bouncycastle.pqc.jcajce.interfaces.FalconPrivateKey;
import com.android.internal.org.bouncycastle.pqc.jcajce.interfaces.FalconPublicKey;
import com.android.internal.org.bouncycastle.pqc.jcajce.provider.util.KeyUtil;
import com.android.internal.org.bouncycastle.pqc.jcajce.spec.FalconParameterSpec;
import com.android.internal.org.bouncycastle.util.Arrays;
import com.android.internal.org.bouncycastle.util.Strings;

public class BCFalconPrivateKey
    implements FalconPrivateKey
{
    private static final long serialVersionUID = 1L;

    private transient FalconPrivateKeyParameters params;
    private transient String algorithm;
    private transient byte[] encoding;
    private transient ASN1Set attributes;

    public BCFalconPrivateKey(
            FalconPrivateKeyParameters params)
    {
        init(params, null);
    }

    public BCFalconPrivateKey(PrivateKeyInfo keyInfo)
            throws IOException
    {
        init(keyInfo);
    }

    private void init(PrivateKeyInfo keyInfo)
            throws IOException
    {
        init((FalconPrivateKeyParameters) PrivateKeyFactory.createKey(keyInfo), keyInfo.getAttributes());
    }

    private void init(FalconPrivateKeyParameters params, ASN1Set attributes)
    {
        this.attributes = attributes;
        this.params = params;
        this.algorithm = Strings.toUpperCase(params.getParameters().getName());
    }

    /**
     * Compare this Falcon private key with another object.
     *
     * @param o the other object
     * @return the result of the comparison
     */
    public boolean equals(Object o)
    {
        if (o == this)
        {
            return true;
        }

        if (o instanceof BCFalconPrivateKey)
        {
            BCFalconPrivateKey otherKey = (BCFalconPrivateKey)o;

            return Arrays.areEqual(getEncoded(), otherKey.getEncoded());
        }

        return false;
    }

    public int hashCode()
    {
        return Arrays.hashCode(getEncoded());
    }

    /**
     * @return name of the algorithm - "FALCON-512 or FALCON-1024"
     */
    public final String getAlgorithm()
    {
        return algorithm;
    }

    public byte[] getEncoded()
    {
        if (encoding == null)
        {
            encoding = KeyUtil.getEncodedPrivateKeyInfo(params, attributes);
        }

        return Arrays.clone(encoding);
    }

    public FalconParameterSpec getParameterSpec()
    {
        return FalconParameterSpec.fromName(params.getParameters().getName());
    }

    public String getFormat()
    {
        return "PKCS#8";
    }

    public FalconPublicKey getPublicKey()
    {
        return new BCFalconPublicKey(new FalconPublicKeyParameters(params.getParameters(), params.getPublicKey()));
    }

    FalconPrivateKeyParameters getKeyParams()
    {
        return params;
    }

    private void readObject(
        ObjectInputStream in)
        throws IOException, ClassNotFoundException
    {
        in.defaultReadObject();

        byte[] enc = (byte[])in.readObject();

        init(PrivateKeyInfo.getInstance(enc));
    }

    private void writeObject(
            ObjectOutputStream out)
            throws IOException
    {
        out.defaultWriteObject();

        out.writeObject(this.getEncoded());
    }
}
