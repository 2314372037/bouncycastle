package com.android.internal.org.bouncycastle.pqc.crypto.xwing;

import java.security.SecureRandom;

import com.android.internal.org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import com.android.internal.org.bouncycastle.crypto.AsymmetricCipherKeyPairGenerator;
import com.android.internal.org.bouncycastle.crypto.KeyGenerationParameters;
import com.android.internal.org.bouncycastle.crypto.generators.X25519KeyPairGenerator;
import com.android.internal.org.bouncycastle.crypto.params.X25519KeyGenerationParameters;
import com.android.internal.org.bouncycastle.pqc.crypto.crystals.kyber.KyberKeyGenerationParameters;
import com.android.internal.org.bouncycastle.pqc.crypto.crystals.kyber.KyberKeyPairGenerator;
import com.android.internal.org.bouncycastle.pqc.crypto.crystals.kyber.KyberParameters;

public class XWingKeyPairGenerator
    implements AsymmetricCipherKeyPairGenerator
{
    private SecureRandom random;

    private void initialize(
        KeyGenerationParameters param)
    {
        this.random = param.getRandom();
    }

    private AsymmetricCipherKeyPair genKeyPair()
    {
        KyberKeyPairGenerator kyberKeyGen = new KyberKeyPairGenerator();

        kyberKeyGen.init(new KyberKeyGenerationParameters(random, KyberParameters.kyber768));

        X25519KeyPairGenerator x25519KeyGen = new X25519KeyPairGenerator();

        x25519KeyGen.init(new X25519KeyGenerationParameters(random));

        AsymmetricCipherKeyPair kybKp = kyberKeyGen.generateKeyPair();
        AsymmetricCipherKeyPair xdhKp = x25519KeyGen.generateKeyPair();

        return new AsymmetricCipherKeyPair(
            new XWingPublicKeyParameters(kybKp.getPublic(), xdhKp.getPublic()),
            new XWingPrivateKeyParameters(kybKp.getPrivate(), xdhKp.getPrivate()));
    }

    public void init(KeyGenerationParameters param)
    {
        this.initialize(param);
    }

    public AsymmetricCipherKeyPair generateKeyPair()
    {
        return genKeyPair();
    }

}
