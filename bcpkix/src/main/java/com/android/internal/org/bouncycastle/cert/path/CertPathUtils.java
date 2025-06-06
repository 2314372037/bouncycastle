package com.android.internal.org.bouncycastle.cert.path;

import java.util.HashSet;
import java.util.Set;

import com.android.internal.org.bouncycastle.cert.X509CertificateHolder;

class CertPathUtils
{
    static Set getCriticalExtensionsOIDs(X509CertificateHolder[] certificates)
    {
        Set criticalExtensions = new HashSet();

        for (int i = 0; i != certificates.length; i++)
        {
            criticalExtensions.addAll(certificates[i].getCriticalExtensionOIDs());
        }

        return criticalExtensions;
    }
}
