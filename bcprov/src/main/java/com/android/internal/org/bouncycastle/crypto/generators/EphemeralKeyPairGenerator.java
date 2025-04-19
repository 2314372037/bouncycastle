package com.android.internal.org.bouncycastle.crypto.generators;

import com.android.internal.org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import com.android.internal.org.bouncycastle.crypto.AsymmetricCipherKeyPairGenerator;
import com.android.internal.org.bouncycastle.crypto.EphemeralKeyPair;
import com.android.internal.org.bouncycastle.crypto.KeyEncoder;

public class EphemeralKeyPairGenerator
{
    private AsymmetricCipherKeyPairGenerator gen;
    private KeyEncoder keyEncoder;

    public EphemeralKeyPairGenerator(AsymmetricCipherKeyPairGenerator gen, KeyEncoder keyEncoder)
    {
        this.gen = gen;
        this.keyEncoder = keyEncoder;
    }

    public EphemeralKeyPair generate()
    {
        AsymmetricCipherKeyPair eph = gen.generateKeyPair();

        // Encode the ephemeral public key
         return new EphemeralKeyPair(eph, keyEncoder);
    }
}
