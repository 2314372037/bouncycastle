package com.android.internal.org.bouncycastle.math.ec.endo;

import com.android.internal.org.bouncycastle.math.ec.ECPoint;
import com.android.internal.org.bouncycastle.math.ec.PreCompInfo;

public class EndoPreCompInfo implements PreCompInfo
{
    protected ECEndomorphism endomorphism;

    protected ECPoint mappedPoint;

    public ECEndomorphism getEndomorphism()
    {
        return endomorphism;
    }

    public void setEndomorphism(ECEndomorphism endomorphism)
    {
        this.endomorphism = endomorphism;
    }

    public ECPoint getMappedPoint()
    {
        return mappedPoint;
    }

    public void setMappedPoint(ECPoint mappedPoint)
    {
        this.mappedPoint = mappedPoint;
    }
}
