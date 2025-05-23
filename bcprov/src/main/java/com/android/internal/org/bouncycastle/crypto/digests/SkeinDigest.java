package com.android.internal.org.bouncycastle.crypto.digests;

import com.android.internal.org.bouncycastle.crypto.CryptoServicePurpose;
import com.android.internal.org.bouncycastle.crypto.CryptoServicesRegistrar;
import com.android.internal.org.bouncycastle.crypto.ExtendedDigest;
import com.android.internal.org.bouncycastle.crypto.engines.ThreefishEngine;
import com.android.internal.org.bouncycastle.crypto.params.SkeinParameters;
import com.android.internal.org.bouncycastle.util.Memoable;

/**
 * Implementation of the Skein parameterised hash function in 256, 512 and 1024 bit block sizes,
 * based on the {@link ThreefishEngine Threefish} tweakable block cipher.
 * <p>
 * This is the 1.3 version of Skein defined in the Skein hash function submission to the NIST SHA-3
 * competition in October 2010.
 * <p>
 * Skein was designed by Niels Ferguson - Stefan Lucks - Bruce Schneier - Doug Whiting - Mihir
 * Bellare - Tadayoshi Kohno - Jon Callas - Jesse Walker.
 *
 * @see SkeinEngine
 * @see SkeinParameters
 */
public class SkeinDigest
    implements ExtendedDigest, Memoable
{
    /**
     * 256 bit block size - Skein-256
     */
    public static final int SKEIN_256 = SkeinEngine.SKEIN_256;
    /**
     * 512 bit block size - Skein-512
     */
    public static final int SKEIN_512 = SkeinEngine.SKEIN_512;
    /**
     * 1024 bit block size - Skein-1024
     */
    public static final int SKEIN_1024 = SkeinEngine.SKEIN_1024;
    private final CryptoServicePurpose purpose;

    private SkeinEngine engine;

    /**
     * Constructs a Skein digest with an internal state size and output size.
     *
     * @param stateSizeBits  the internal state size in bits - one of {@link #SKEIN_256}, {@link #SKEIN_512} or
     *                       {@link #SKEIN_1024}.
     * @param digestSizeBits the output/digest size to produce in bits, which must be an integral number of
     *                       bytes.
     */

    public SkeinDigest(int stateSizeBits, int digestSizeBits)
    {
        this(stateSizeBits, digestSizeBits, CryptoServicePurpose.ANY);
    }
    public SkeinDigest(int stateSizeBits, int digestSizeBits, CryptoServicePurpose purpose)
    {
        this.engine = new SkeinEngine(stateSizeBits, digestSizeBits);
        this.purpose = purpose;

        init(null);
        CryptoServicesRegistrar.checkConstraints(Utils.getDefaultProperties(this, getDigestSize() * 4, purpose));

    }

    public SkeinDigest(SkeinDigest digest)
    {
        this.engine = new SkeinEngine(digest.engine);
        this.purpose = digest.purpose;

        CryptoServicesRegistrar.checkConstraints(Utils.getDefaultProperties(this, digest.getDigestSize() * 4, purpose));

    }

    public void reset(Memoable other)
    {
        SkeinDigest d = (SkeinDigest)other;
        engine.reset(d.engine);
    }

    public Memoable copy()
    {
        return new SkeinDigest(this);
    }

    public String getAlgorithmName()
    {
        return "Skein-" + (engine.getBlockSize() * 8) + "-" + (engine.getOutputSize() * 8);
    }

    public int getDigestSize()
    {
        return engine.getOutputSize();
    }

    public int getByteLength()
    {
        return engine.getBlockSize();
    }

    /**
     * Optionally initialises the Skein digest with the provided parameters.<br>
     * See {@link SkeinParameters} for details on the parameterisation of the Skein hash function.
     *
     * @param params the parameters to apply to this engine, or <code>null</code> to use no parameters.
     */
    public void init(SkeinParameters params)
    {
        engine.init(params);
    }

    public void reset()
    {
        engine.reset();
    }

    public void update(byte in)
    {
        engine.update(in);
    }

    public void update(byte[] in, int inOff, int len)
    {
        engine.update(in, inOff, len);
    }

    public int doFinal(byte[] out, int outOff)
    {
        return engine.doFinal(out, outOff);
    }

}
