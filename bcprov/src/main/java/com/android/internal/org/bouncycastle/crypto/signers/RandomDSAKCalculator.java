package com.android.internal.org.bouncycastle.crypto.signers;

import java.math.BigInteger;
import java.security.SecureRandom;

import com.android.internal.org.bouncycastle.util.BigIntegers;

public class RandomDSAKCalculator
    implements DSAKCalculator
{
    private static final BigInteger ZERO = BigInteger.valueOf(0);

    private BigInteger q;
    private SecureRandom random;

    public boolean isDeterministic()
    {
        return false;
    }

    public void init(BigInteger n, SecureRandom random)
    {
        this.q = n;
        this.random = random;
    }

    public void init(BigInteger n, BigInteger d, byte[] message)
    {
        throw new IllegalStateException("Operation not supported");
    }

    public BigInteger nextK()
    {
        int qBitLength = q.bitLength();

        BigInteger k;
        do
        {
            k = BigIntegers.createRandomBigInteger(qBitLength, random);
        }
        while (k.equals(ZERO) || k.compareTo(q) >= 0);

        return k;
    }
}
