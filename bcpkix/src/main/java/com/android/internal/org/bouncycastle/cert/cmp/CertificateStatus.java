package com.android.internal.org.bouncycastle.cert.cmp;

import java.math.BigInteger;

import com.android.internal.org.bouncycastle.asn1.cmp.CMPCertificate;
import com.android.internal.org.bouncycastle.asn1.cmp.CertStatus;
import com.android.internal.org.bouncycastle.asn1.cmp.PKIStatusInfo;
import com.android.internal.org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import com.android.internal.org.bouncycastle.cert.X509CertificateHolder;
import com.android.internal.org.bouncycastle.operator.DigestAlgorithmIdentifierFinder;
import com.android.internal.org.bouncycastle.operator.DigestCalculator;
import com.android.internal.org.bouncycastle.operator.DigestCalculatorProvider;
import com.android.internal.org.bouncycastle.operator.OperatorCreationException;
import com.android.internal.org.bouncycastle.util.Arrays;

public class CertificateStatus
{
    private DigestAlgorithmIdentifierFinder digestAlgFinder;    
    private CertStatus certStatus;

    CertificateStatus(DigestAlgorithmIdentifierFinder digestAlgFinder, CertStatus certStatus)
    {
        this.digestAlgFinder = digestAlgFinder;
        this.certStatus = certStatus;
    }

    public PKIStatusInfo getStatusInfo()
    {
        return certStatus.getStatusInfo();
    }

    public BigInteger getCertRequestID()
    {
        return certStatus.getCertReqId().getValue();
    }

    public boolean isVerified(X509CertificateHolder certHolder, DigestCalculatorProvider digesterProvider)
        throws CMPException
    {
        return isVerified(new CMPCertificate(certHolder.toASN1Structure()), certHolder.getSignatureAlgorithm(),
            digesterProvider);
    }

    public boolean isVerified(CMPCertificate cmpCert, AlgorithmIdentifier signatureAlgorithm,
        DigestCalculatorProvider digesterProvider)
        throws CMPException
    {
        byte[] certHash = CMPUtil.calculateCertHash(cmpCert, signatureAlgorithm, digesterProvider, digestAlgFinder);

        return Arrays.constantTimeAreEqual(certStatus.getCertHash().getOctets(), certHash);
    }
}
