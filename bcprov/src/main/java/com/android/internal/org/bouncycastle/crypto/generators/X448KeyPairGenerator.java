package com.android.internal.org.bouncycastle.crypto.generators;

import java.security.SecureRandom;

import com.android.internal.org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import com.android.internal.org.bouncycastle.crypto.AsymmetricCipherKeyPairGenerator;
import com.android.internal.org.bouncycastle.crypto.CryptoServicePurpose;
import com.android.internal.org.bouncycastle.crypto.CryptoServicesRegistrar;
import com.android.internal.org.bouncycastle.crypto.KeyGenerationParameters;
import com.android.internal.org.bouncycastle.crypto.constraints.DefaultServiceProperties;
import com.android.internal.org.bouncycastle.crypto.params.X448PrivateKeyParameters;
import com.android.internal.org.bouncycastle.crypto.params.X448PublicKeyParameters;

public class X448KeyPairGenerator
    implements AsymmetricCipherKeyPairGenerator
{
    private SecureRandom random;

    public void init(KeyGenerationParameters parameters)
    {
        this.random = parameters.getRandom();

        CryptoServicesRegistrar.checkConstraints(new DefaultServiceProperties("X448KeyGen", 224, null, CryptoServicePurpose.KEYGEN));
    }

    public AsymmetricCipherKeyPair generateKeyPair()
    {
        X448PrivateKeyParameters privateKey = new X448PrivateKeyParameters(random);
        X448PublicKeyParameters publicKey = privateKey.generatePublicKey();
        return new AsymmetricCipherKeyPair(publicKey, privateKey);
    }
}
