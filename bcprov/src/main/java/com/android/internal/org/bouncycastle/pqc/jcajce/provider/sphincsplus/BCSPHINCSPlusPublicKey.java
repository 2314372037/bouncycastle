package com.android.internal.org.bouncycastle.pqc.jcajce.provider.sphincsplus;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;

import com.android.internal.org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import com.android.internal.org.bouncycastle.crypto.CipherParameters;
import com.android.internal.org.bouncycastle.pqc.crypto.sphincsplus.SPHINCSPlusPublicKeyParameters;
import com.android.internal.org.bouncycastle.pqc.crypto.util.PublicKeyFactory;
import com.android.internal.org.bouncycastle.pqc.crypto.util.SubjectPublicKeyInfoFactory;
import com.android.internal.org.bouncycastle.pqc.jcajce.interfaces.SPHINCSPlusPublicKey;
import com.android.internal.org.bouncycastle.pqc.jcajce.spec.SPHINCSPlusParameterSpec;
import com.android.internal.org.bouncycastle.util.Arrays;
import com.android.internal.org.bouncycastle.util.Strings;

public class BCSPHINCSPlusPublicKey
    implements SPHINCSPlusPublicKey
{
    private static final long serialVersionUID = 1L;

    private transient SPHINCSPlusPublicKeyParameters params;

    public BCSPHINCSPlusPublicKey(
        SPHINCSPlusPublicKeyParameters params)
    {
        this.params = params;
    }

    public BCSPHINCSPlusPublicKey(SubjectPublicKeyInfo keyInfo)
        throws IOException
    {
        init(keyInfo);
    }

    private void init(SubjectPublicKeyInfo keyInfo)
        throws IOException
    {
        this.params = (SPHINCSPlusPublicKeyParameters)PublicKeyFactory.createKey(keyInfo);
    }
    
    /**
     * Compare this SPHINCS-256 public key with another object.
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

        if (o instanceof BCSPHINCSPlusPublicKey)
        {
            BCSPHINCSPlusPublicKey otherKey = (BCSPHINCSPlusPublicKey)o;

            return Arrays.areEqual(params.getEncoded(), otherKey.params.getEncoded());
        }

        return false;
    }

    public int hashCode()
    {
        return Arrays.hashCode(params.getEncoded());
    }

    /**
     * @return name of the algorithm - "SPHINCS+" followed by the parameter type.
     */
    public final String getAlgorithm()
    {
        return "SPHINCS+" + "-" + Strings.toUpperCase(params.getParameters().getName());
    }

    public byte[] getEncoded()
    {
        try
        {
            SubjectPublicKeyInfo pki = SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(params);

            return pki.getEncoded();
        }
        catch (IOException e)
        {
            return null;
        }
    }

    public String getFormat()
    {
        return "X.509";
    }

    public SPHINCSPlusParameterSpec getParameterSpec()
    {
        return SPHINCSPlusParameterSpec.fromName(params.getParameters().getName());
    }

    CipherParameters getKeyParams()
    {
        return params;
    }

    private void readObject(
        ObjectInputStream in)
        throws IOException, ClassNotFoundException
    {
        in.defaultReadObject();

        byte[] enc = (byte[])in.readObject();

        init(SubjectPublicKeyInfo.getInstance(enc));
    }

    private void writeObject(
        ObjectOutputStream out)
        throws IOException
    {
        out.defaultWriteObject();

        out.writeObject(this.getEncoded());
    }
}
