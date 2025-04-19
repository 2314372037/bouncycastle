package com.android.internal.org.bouncycastle.operator.bc;

import com.android.internal.org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import com.android.internal.org.bouncycastle.crypto.Digest;
import com.android.internal.org.bouncycastle.crypto.Signer;
import com.android.internal.org.bouncycastle.crypto.signers.DSADigestSigner;
import com.android.internal.org.bouncycastle.crypto.signers.DSASigner;
import com.android.internal.org.bouncycastle.operator.OperatorCreationException;

public class BcDSAContentSignerBuilder
    extends BcContentSignerBuilder
{
    public BcDSAContentSignerBuilder(AlgorithmIdentifier sigAlgId, AlgorithmIdentifier digAlgId)
    {
        super(sigAlgId, digAlgId);
    }

    protected Signer createSigner(AlgorithmIdentifier sigAlgId, AlgorithmIdentifier digAlgId)
        throws OperatorCreationException
    {
        Digest dig = digestProvider.get(digAlgId);

        return new DSADigestSigner(new DSASigner(), dig);
    }
}
