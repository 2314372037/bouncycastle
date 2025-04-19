package com.android.internal.org.bouncycastle.operator.bc;

import java.io.IOException;

import com.android.internal.org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import com.android.internal.org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import com.android.internal.org.bouncycastle.crypto.Digest;
import com.android.internal.org.bouncycastle.crypto.Signer;
import com.android.internal.org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import com.android.internal.org.bouncycastle.crypto.signers.DSADigestSigner;
import com.android.internal.org.bouncycastle.crypto.signers.DSASigner;
import com.android.internal.org.bouncycastle.crypto.util.PublicKeyFactory;
import com.android.internal.org.bouncycastle.operator.DigestAlgorithmIdentifierFinder;
import com.android.internal.org.bouncycastle.operator.OperatorCreationException;

public class BcDSAContentVerifierProviderBuilder
    extends BcContentVerifierProviderBuilder
{
    private DigestAlgorithmIdentifierFinder digestAlgorithmFinder;

    public BcDSAContentVerifierProviderBuilder(DigestAlgorithmIdentifierFinder digestAlgorithmFinder)
    {
        this.digestAlgorithmFinder = digestAlgorithmFinder;
    }

    protected Signer createSigner(AlgorithmIdentifier sigAlgId)
        throws OperatorCreationException
    {
        AlgorithmIdentifier digAlg = digestAlgorithmFinder.find(sigAlgId);
        Digest dig = digestProvider.get(digAlg);

        return new DSADigestSigner(new DSASigner(), dig);
    }

    protected AsymmetricKeyParameter extractKeyParameters(SubjectPublicKeyInfo publicKeyInfo)
        throws IOException
    {
        return PublicKeyFactory.createKey(publicKeyInfo);
    }
}
