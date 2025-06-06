package com.android.internal.org.bouncycastle.crypto.signers;

import com.android.internal.org.bouncycastle.crypto.CipherParameters;
import com.android.internal.org.bouncycastle.crypto.CryptoServicesRegistrar;
import com.android.internal.org.bouncycastle.crypto.Signer;
import com.android.internal.org.bouncycastle.crypto.Xof;
import com.android.internal.org.bouncycastle.crypto.params.Ed448PrivateKeyParameters;
import com.android.internal.org.bouncycastle.crypto.params.Ed448PublicKeyParameters;
import com.android.internal.org.bouncycastle.math.ec.rfc8032.Ed448;
import com.android.internal.org.bouncycastle.util.Arrays;

public class Ed448phSigner
    implements Signer
{
    private final Xof prehash = Ed448.createPrehash();
    private final byte[] context;

    private boolean forSigning;
    private Ed448PrivateKeyParameters privateKey;
    private Ed448PublicKeyParameters publicKey;

    public Ed448phSigner(byte[] context)
    {
        if (null == context)
        {
            throw new NullPointerException("'context' cannot be null");
        }

        this.context = Arrays.clone(context);
    }

    public void init(boolean forSigning, CipherParameters parameters)
    {
        this.forSigning = forSigning;

        if (forSigning)
        {
            this.privateKey = (Ed448PrivateKeyParameters)parameters;
            this.publicKey = null;
        }
        else
        {
            this.privateKey = null;
            this.publicKey = (Ed448PublicKeyParameters)parameters;
        }

        CryptoServicesRegistrar.checkConstraints(Utils.getDefaultProperties("Ed448", 224, parameters, forSigning));

        reset();
    }

    public void update(byte b)
    {
        prehash.update(b);
    }

    public void update(byte[] buf, int off, int len)
    {
        prehash.update(buf, off, len);
    }

    public byte[] generateSignature()
    {
        if (!forSigning || null == privateKey)
        {
            throw new IllegalStateException("Ed448phSigner not initialised for signature generation.");
        }

        byte[] msg = new byte[Ed448.PREHASH_SIZE];
        if (Ed448.PREHASH_SIZE != prehash.doFinal(msg, 0, Ed448.PREHASH_SIZE))
        {
            throw new IllegalStateException("Prehash digest failed");
        }

        byte[] signature = new byte[Ed448PrivateKeyParameters.SIGNATURE_SIZE];
        privateKey.sign(Ed448.Algorithm.Ed448ph, context, msg, 0, Ed448.PREHASH_SIZE, signature, 0);
        return signature;
    }

    public boolean verifySignature(byte[] signature)
    {
        if (forSigning || null == publicKey)
        {
            throw new IllegalStateException("Ed448phSigner not initialised for verification");
        }
        if (Ed448.SIGNATURE_SIZE != signature.length)
        {
            prehash.reset();
            return false;
        }

        byte[] msg = new byte[Ed448.PREHASH_SIZE];
        if (Ed448.PREHASH_SIZE != prehash. doFinal(msg, 0, Ed448.PREHASH_SIZE))
        {
            throw new IllegalStateException("Prehash digest failed");
        }

        return publicKey.verify(Ed448.Algorithm.Ed448ph, context, msg, 0, Ed448.PREHASH_SIZE, signature, 0);
    }

    public void reset()
    {
        prehash.reset();
    }
}
