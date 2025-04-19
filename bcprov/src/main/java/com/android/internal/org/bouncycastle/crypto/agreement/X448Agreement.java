package com.android.internal.org.bouncycastle.crypto.agreement;

import com.android.internal.org.bouncycastle.crypto.CipherParameters;
import com.android.internal.org.bouncycastle.crypto.CryptoServicesRegistrar;
import com.android.internal.org.bouncycastle.crypto.RawAgreement;
import com.android.internal.org.bouncycastle.crypto.params.X448PrivateKeyParameters;
import com.android.internal.org.bouncycastle.crypto.params.X448PublicKeyParameters;

public final class X448Agreement
    implements RawAgreement
{
    private X448PrivateKeyParameters privateKey;

    public void init(CipherParameters parameters)
    {
        this.privateKey = (X448PrivateKeyParameters)parameters;

        CryptoServicesRegistrar.checkConstraints(Utils.getDefaultProperties("X448", this.privateKey));
    }

    public int getAgreementSize()
    {
        return X448PrivateKeyParameters.SECRET_SIZE;
    }

    public void calculateAgreement(CipherParameters publicKey, byte[] buf, int off)
    {
        privateKey.generateSecret((X448PublicKeyParameters)publicKey, buf, off);
    }
}
