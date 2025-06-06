package com.android.internal.org.bouncycastle.oer.its.template.etsi102941;

import com.android.internal.org.bouncycastle.oer.OERDefinition;
import com.android.internal.org.bouncycastle.oer.its.template.etsi102941.basetypes.EtsiTs102941BaseTypes;

public class EtsiTs102941TypesCaManagement
{
    /**
     * CaCertificateRequest ::= SEQUENCE {
     * publicKeys                  PublicKeys,
     * requestedSubjectAttributes  CertificateSubjectAttributes,
     * ...
     * }
     */
    public static final OERDefinition.Builder CaCertificateRequest = OERDefinition.seq(
        EtsiTs102941BaseTypes.PublicKeys.label("publicKeys"),
        EtsiTs102941BaseTypes.CertificateSubjectAttributes.label("requestedSubjectAttributes")
    ).typeName("CaCertificateRequest");
}
