package com.android.internal.org.bouncycastle.operator.bc;

import com.android.internal.org.bouncycastle.asn1.edec.EdECObjectIdentifiers;
import com.android.internal.org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import com.android.internal.org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import com.android.internal.org.bouncycastle.crypto.Signer;
import com.android.internal.org.bouncycastle.crypto.signers.Ed25519Signer;
import com.android.internal.org.bouncycastle.operator.OperatorCreationException;

public class BcEdECContentSignerBuilder
    extends BcContentSignerBuilder
{
    public BcEdECContentSignerBuilder(AlgorithmIdentifier sigAlgId)
    {
        super(sigAlgId, new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha512));
    }

    protected Signer createSigner(AlgorithmIdentifier sigAlgId, AlgorithmIdentifier digAlgId)
        throws OperatorCreationException
    {
        if (sigAlgId.getAlgorithm().equals(EdECObjectIdentifiers.id_Ed25519))
        {
            return new Ed25519Signer();
        }

        throw new IllegalStateException("unknown signature type");
    }
}
