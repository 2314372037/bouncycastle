package com.android.internal.org.bouncycastle.crypto.generators;

import java.math.BigInteger;

import com.android.internal.org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import com.android.internal.org.bouncycastle.crypto.AsymmetricCipherKeyPairGenerator;
import com.android.internal.org.bouncycastle.crypto.CryptoServicePurpose;
import com.android.internal.org.bouncycastle.crypto.CryptoServicesRegistrar;
import com.android.internal.org.bouncycastle.crypto.KeyGenerationParameters;
import com.android.internal.org.bouncycastle.crypto.constraints.ConstraintUtils;
import com.android.internal.org.bouncycastle.crypto.constraints.DefaultServiceProperties;
import com.android.internal.org.bouncycastle.crypto.params.DHKeyGenerationParameters;
import com.android.internal.org.bouncycastle.crypto.params.DHParameters;
import com.android.internal.org.bouncycastle.crypto.params.DHPrivateKeyParameters;
import com.android.internal.org.bouncycastle.crypto.params.DHPublicKeyParameters;

/**
 * a Diffie-Hellman key pair generator.
 *
 * This generates keys consistent for use in the MTI/A0 key agreement protocol
 * as described in "Handbook of Applied Cryptography", Pages 516-519.
 */
public class DHKeyPairGenerator
    implements AsymmetricCipherKeyPairGenerator
{
    private DHKeyGenerationParameters param;

    public void init(
        KeyGenerationParameters param)
    {
        this.param = (DHKeyGenerationParameters)param;

        CryptoServicesRegistrar.checkConstraints(new DefaultServiceProperties("DHKeyGen", ConstraintUtils.bitsOfSecurityFor(this.param.getParameters().getP()), this.param.getParameters(), CryptoServicePurpose.KEYGEN));
    }

    public AsymmetricCipherKeyPair generateKeyPair()
    {
        DHKeyGeneratorHelper helper = DHKeyGeneratorHelper.INSTANCE;
        DHParameters dhp = param.getParameters();

        BigInteger x = helper.calculatePrivate(dhp, param.getRandom()); 
        BigInteger y = helper.calculatePublic(dhp, x);

        return new AsymmetricCipherKeyPair(
            new DHPublicKeyParameters(y, dhp),
            new DHPrivateKeyParameters(x, dhp));
    }
}
