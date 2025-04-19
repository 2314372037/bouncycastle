package com.android.internal.org.bouncycastle.its.bc;

import com.android.internal.org.bouncycastle.its.ITSCertificate;
import com.android.internal.org.bouncycastle.its.ITSImplicitCertificateBuilder;
import com.android.internal.org.bouncycastle.oer.its.ieee1609dot2.ToBeSignedCertificate;
import com.android.internal.org.bouncycastle.operator.bc.BcDigestCalculatorProvider;

public class BcITSImplicitCertificateBuilder
    extends ITSImplicitCertificateBuilder
{
    public BcITSImplicitCertificateBuilder(ITSCertificate issuer, ToBeSignedCertificate.Builder tbsCertificate)
    {
        super(issuer, new BcDigestCalculatorProvider(), tbsCertificate);
    }
}
