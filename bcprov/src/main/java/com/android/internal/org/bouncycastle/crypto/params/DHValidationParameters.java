package com.android.internal.org.bouncycastle.crypto.params;

import com.android.internal.org.bouncycastle.util.Arrays;

public class DHValidationParameters
{
    private byte[]  seed;
    private int     counter;

    public DHValidationParameters(
        byte[]  seed,
        int     counter)
    {
        this.seed = Arrays.clone(seed);
        this.counter = counter;
    }

    public int getCounter()
    {
        return counter;
    }

    public byte[] getSeed()
    {
        return Arrays.clone(seed);
    }

    public boolean equals(
        Object o)
    {
        if (!(o instanceof DHValidationParameters))
        {
            return false;
        }

        DHValidationParameters  other = (DHValidationParameters)o;

        if (other.counter != this.counter)
        {
            return false;
        }

        return Arrays.areEqual(this.seed, other.seed);
    }

    public int hashCode()
    {
        return counter ^ Arrays.hashCode(seed);
    }
}
