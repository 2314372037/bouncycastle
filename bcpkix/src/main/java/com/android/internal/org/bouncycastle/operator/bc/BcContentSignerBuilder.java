package com.android.internal.org.bouncycastle.operator.bc;

import java.io.OutputStream;
import java.security.SecureRandom;
import java.util.Map;

import com.android.internal.org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import com.android.internal.org.bouncycastle.crypto.CryptoException;
import com.android.internal.org.bouncycastle.crypto.Signer;
import com.android.internal.org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import com.android.internal.org.bouncycastle.crypto.params.ParametersWithRandom;
import com.android.internal.org.bouncycastle.operator.ContentSigner;
import com.android.internal.org.bouncycastle.operator.OperatorCreationException;
import com.android.internal.org.bouncycastle.operator.RuntimeOperatorException;

public abstract class BcContentSignerBuilder
{
    private SecureRandom random;
    private AlgorithmIdentifier sigAlgId;
    private AlgorithmIdentifier digAlgId;

    protected BcDigestProvider                digestProvider;

    public BcContentSignerBuilder(AlgorithmIdentifier sigAlgId, AlgorithmIdentifier digAlgId)
    {
        this.sigAlgId = sigAlgId;
        this.digAlgId = digAlgId;
        this.digestProvider = BcDefaultDigestProvider.INSTANCE;
    }

    public BcContentSignerBuilder setSecureRandom(SecureRandom random)
    {
        this.random = random;

        return this;
    }

    public ContentSigner build(AsymmetricKeyParameter privateKey)
        throws OperatorCreationException
    {
        final Signer sig = createSigner(sigAlgId, digAlgId);

        if (random != null)
        {
            sig.init(true, new ParametersWithRandom(privateKey, random));
        }
        else
        {
            sig.init(true, privateKey);
        }

        return new ContentSigner()
        {
            private BcSignerOutputStream stream = new BcSignerOutputStream(sig);

            public AlgorithmIdentifier getAlgorithmIdentifier()
            {
                return sigAlgId;
            }

            public OutputStream getOutputStream()
            {
                return stream;
            }

            public byte[] getSignature()
            {
                try
                {
                    return stream.getSignature();
                }
                catch (CryptoException e)
                {
                    throw new RuntimeOperatorException("exception obtaining signature: " + e.getMessage(), e);
                }
            }
        };
    }

    protected abstract Signer createSigner(AlgorithmIdentifier sigAlgId, AlgorithmIdentifier algorithmIdentifier)
        throws OperatorCreationException;
}
