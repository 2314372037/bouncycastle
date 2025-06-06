package com.android.internal.org.bouncycastle.crypto.signers;

import com.android.internal.org.bouncycastle.crypto.CipherParameters;
import com.android.internal.org.bouncycastle.crypto.CryptoServicesRegistrar;
import com.android.internal.org.bouncycastle.crypto.Digest;
import com.android.internal.org.bouncycastle.crypto.Signer;
import com.android.internal.org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters;
import com.android.internal.org.bouncycastle.crypto.params.Ed25519PublicKeyParameters;
import com.android.internal.org.bouncycastle.math.ec.rfc8032.Ed25519;
import com.android.internal.org.bouncycastle.util.Arrays;

public class Ed25519phSigner
    implements Signer
{
    private final Digest prehash = Ed25519.createPrehash();
    private final byte[] context;

    private boolean forSigning;
    private Ed25519PrivateKeyParameters privateKey;
    private Ed25519PublicKeyParameters publicKey;

    public Ed25519phSigner(byte[] context)
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
            this.privateKey = (Ed25519PrivateKeyParameters)parameters;
            this.publicKey = null;
        }
        else
        {
            this.privateKey = null;
            this.publicKey = (Ed25519PublicKeyParameters)parameters;
        }

        CryptoServicesRegistrar.checkConstraints(Utils.getDefaultProperties("Ed25519", 128, parameters, forSigning));

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
            throw new IllegalStateException("Ed25519phSigner not initialised for signature generation.");
        }

        byte[] msg = new byte[Ed25519.PREHASH_SIZE];
        if (Ed25519.PREHASH_SIZE != prehash.doFinal(msg, 0))
        {
            throw new IllegalStateException("Prehash digest failed");
        }

        byte[] signature = new byte[Ed25519PrivateKeyParameters.SIGNATURE_SIZE];
        privateKey.sign(Ed25519.Algorithm.Ed25519ph, context, msg, 0, Ed25519.PREHASH_SIZE, signature, 0);
        return signature;
    }

    public boolean verifySignature(byte[] signature)
    {
        if (forSigning || null == publicKey)
        {
            throw new IllegalStateException("Ed25519phSigner not initialised for verification");
        }
        if (Ed25519.SIGNATURE_SIZE != signature.length)
        {
            prehash.reset();
            return false;
        }

        byte[] msg = new byte[Ed25519.PREHASH_SIZE];
        if (Ed25519.PREHASH_SIZE != prehash.doFinal(msg, 0))
        {
            throw new IllegalStateException("Prehash digest failed");
        }

        return publicKey.verify(Ed25519.Algorithm.Ed25519ph, context, msg, 0, Ed25519.PREHASH_SIZE, signature, 0);
    }

    public void reset()
    {
        prehash.reset();
    }
}
