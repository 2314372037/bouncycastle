package com.android.internal.org.bouncycastle.math.ec;

import java.math.BigInteger;

public abstract class AbstractECMultiplier implements ECMultiplier
{
    public ECPoint multiply(ECPoint p, BigInteger k)
    {
        int sign = k.signum();
        if (sign == 0 || p.isInfinity())
        {
            return p.getCurve().getInfinity();
        }

        ECPoint positive = multiplyPositive(p, k.abs());
        ECPoint result = sign > 0 ? positive : positive.negate();

        /*
         * Although the various multipliers ought not to produce invalid output under normal
         * circumstances, a final check here is advised to guard against fault attacks.
         */
        return checkResult(result);
    }

    protected abstract ECPoint multiplyPositive(ECPoint p, BigInteger k);

    protected ECPoint checkResult(ECPoint p)
    {
        return ECAlgorithms.implCheckResult(p);
    }
}
