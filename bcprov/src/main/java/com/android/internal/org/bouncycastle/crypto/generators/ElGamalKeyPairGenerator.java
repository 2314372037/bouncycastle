package com.android.internal.org.bouncycastle.crypto.generators;

import java.math.BigInteger;

import com.android.internal.org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import com.android.internal.org.bouncycastle.crypto.AsymmetricCipherKeyPairGenerator;
import com.android.internal.org.bouncycastle.crypto.CryptoServicePurpose;
import com.android.internal.org.bouncycastle.crypto.CryptoServicesRegistrar;
import com.android.internal.org.bouncycastle.crypto.KeyGenerationParameters;
import com.android.internal.org.bouncycastle.crypto.constraints.ConstraintUtils;
import com.android.internal.org.bouncycastle.crypto.constraints.DefaultServiceProperties;
import com.android.internal.org.bouncycastle.crypto.params.DHParameters;
import com.android.internal.org.bouncycastle.crypto.params.ElGamalKeyGenerationParameters;
import com.android.internal.org.bouncycastle.crypto.params.ElGamalParameters;
import com.android.internal.org.bouncycastle.crypto.params.ElGamalPrivateKeyParameters;
import com.android.internal.org.bouncycastle.crypto.params.ElGamalPublicKeyParameters;

/**
 * a ElGamal key pair generator.
 * <p>
 * This generates keys consistent for use with ElGamal as described in
 * page 164 of "Handbook of Applied Cryptography".
 */
public class ElGamalKeyPairGenerator
    implements AsymmetricCipherKeyPairGenerator
{
    private ElGamalKeyGenerationParameters param;

    public void init(
        KeyGenerationParameters param)
    {
        this.param = (ElGamalKeyGenerationParameters)param;

        CryptoServicesRegistrar.checkConstraints(new DefaultServiceProperties("ElGamalKeyGen", ConstraintUtils.bitsOfSecurityFor(this.param.getParameters().getP()), this.param.getParameters(), CryptoServicePurpose.KEYGEN));
    }

    public AsymmetricCipherKeyPair generateKeyPair()
    {
        DHKeyGeneratorHelper helper = DHKeyGeneratorHelper.INSTANCE;
        ElGamalParameters egp = param.getParameters();
        DHParameters dhp = new DHParameters(egp.getP(), egp.getG(), null, egp.getL());  

        BigInteger x = helper.calculatePrivate(dhp, param.getRandom()); 
        BigInteger y = helper.calculatePublic(dhp, x);

        return new AsymmetricCipherKeyPair(
            new ElGamalPublicKeyParameters(y, egp),
            new ElGamalPrivateKeyParameters(x, egp));
    }
}
