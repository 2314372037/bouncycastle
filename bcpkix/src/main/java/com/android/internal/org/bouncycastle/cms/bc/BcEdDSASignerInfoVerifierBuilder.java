package com.android.internal.org.bouncycastle.cms.bc;

import com.android.internal.org.bouncycastle.cert.X509CertificateHolder;
import com.android.internal.org.bouncycastle.cms.CMSSignatureAlgorithmNameGenerator;
import com.android.internal.org.bouncycastle.cms.SignerInformationVerifier;
import com.android.internal.org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import com.android.internal.org.bouncycastle.operator.DigestAlgorithmIdentifierFinder;
import com.android.internal.org.bouncycastle.operator.DigestCalculatorProvider;
import com.android.internal.org.bouncycastle.operator.OperatorCreationException;
import com.android.internal.org.bouncycastle.operator.SignatureAlgorithmIdentifierFinder;
import com.android.internal.org.bouncycastle.operator.bc.BcEdDSAContentVerifierProviderBuilder;

public class BcEdDSASignerInfoVerifierBuilder
{
    private BcEdDSAContentVerifierProviderBuilder contentVerifierProviderBuilder;
    private DigestCalculatorProvider digestCalculatorProvider;
    private CMSSignatureAlgorithmNameGenerator sigAlgNameGen;
    private SignatureAlgorithmIdentifierFinder sigAlgIdFinder;

    public BcEdDSASignerInfoVerifierBuilder(CMSSignatureAlgorithmNameGenerator sigAlgNameGen, SignatureAlgorithmIdentifierFinder sigAlgIdFinder, DigestAlgorithmIdentifierFinder digestAlgorithmFinder, DigestCalculatorProvider digestCalculatorProvider)
    {
        this.sigAlgNameGen = sigAlgNameGen;
        this.sigAlgIdFinder = sigAlgIdFinder;
        this.contentVerifierProviderBuilder = new BcEdDSAContentVerifierProviderBuilder();
        this.digestCalculatorProvider = digestCalculatorProvider;
    }

    public SignerInformationVerifier build(X509CertificateHolder certHolder)
        throws OperatorCreationException
    {
        return new SignerInformationVerifier(sigAlgNameGen, sigAlgIdFinder, contentVerifierProviderBuilder.build(certHolder), digestCalculatorProvider);
    }

    public SignerInformationVerifier build(AsymmetricKeyParameter pubKey)
        throws OperatorCreationException
    {
        return new SignerInformationVerifier(sigAlgNameGen, sigAlgIdFinder, contentVerifierProviderBuilder.build(pubKey), digestCalculatorProvider);
    }
}
