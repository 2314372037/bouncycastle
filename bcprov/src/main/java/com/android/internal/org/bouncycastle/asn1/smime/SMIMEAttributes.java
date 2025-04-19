package com.android.internal.org.bouncycastle.asn1.smime;

import com.android.internal.org.bouncycastle.asn1.ASN1ObjectIdentifier;
import com.android.internal.org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;

public interface SMIMEAttributes
{
    ASN1ObjectIdentifier  smimeCapabilities = PKCSObjectIdentifiers.pkcs_9_at_smimeCapabilities;
    ASN1ObjectIdentifier  encrypKeyPref = PKCSObjectIdentifiers.id_aa_encrypKeyPref;
}
