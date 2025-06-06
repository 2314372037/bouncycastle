package com.android.internal.org.bouncycastle.crypto.fpe;

import com.android.internal.org.bouncycastle.crypto.BlockCipher;
import com.android.internal.org.bouncycastle.crypto.CipherParameters;
import com.android.internal.org.bouncycastle.crypto.engines.AESEngine;
import com.android.internal.org.bouncycastle.crypto.params.FPEParameters;
import com.android.internal.org.bouncycastle.util.Properties;

/**
 * NIST SP 800-38G, FF1 format preserving encryption.
 */
public class FPEFF1Engine
    extends FPEEngine
{

    /**
     * Base constructor - the engine will use AES.
     */
    public FPEFF1Engine()
    {
        this(AESEngine.newInstance());
    }

    /**
     * Build the engine using the specified 128 bit block cipher.
     *
     * @param baseCipher cipher to base the FPE algorithm on.
     */
    public FPEFF1Engine(BlockCipher baseCipher)
    {
        super(baseCipher);

        if (baseCipher.getBlockSize() != 16)
        {
            throw new IllegalArgumentException("base cipher needs to be 128 bits");
        }

        if (Properties.isOverrideSet(SP80038G.FPE_DISABLED)
            || Properties.isOverrideSet(SP80038G.FF1_DISABLED))
        {
            throw new UnsupportedOperationException("FF1 encryption disabled");
        }
    }

    public void init(boolean forEncryption, CipherParameters parameters)
    {
        this.forEncryption = forEncryption;

        this.fpeParameters = (FPEParameters)parameters;

        baseCipher.init(!fpeParameters.isUsingInverseFunction(), fpeParameters.getKey());
    }

    public String getAlgorithmName()
    {
        return "FF1";
    }

    protected int encryptBlock(byte[] inBuf, int inOff, int length, byte[] outBuf, int outOff)
    {
        byte[] enc;

        if (fpeParameters.getRadix() > 256)
        {
            enc = toByteArray(SP80038G.encryptFF1w(baseCipher, fpeParameters.getRadixConverter(), fpeParameters.getTweak(), toShortArray(inBuf), inOff, length / 2));
        }
        else
        {
            enc = SP80038G.encryptFF1(baseCipher, fpeParameters.getRadixConverter(), fpeParameters.getTweak(), inBuf, inOff, length);
        }

        System.arraycopy(enc, 0, outBuf, outOff, length);

        return length;
    }

    protected int decryptBlock(byte[] inBuf, int inOff, int length, byte[] outBuf, int outOff)
    {
        byte[] dec;

        if (fpeParameters.getRadix() > 256)
        {
            dec = toByteArray(SP80038G.decryptFF1w(baseCipher, fpeParameters.getRadixConverter(), fpeParameters.getTweak(), toShortArray(inBuf), inOff, length / 2));
        }
        else
        {
            dec = SP80038G.decryptFF1(baseCipher, fpeParameters.getRadixConverter(), fpeParameters.getTweak(), inBuf, inOff, length);
        }

        System.arraycopy(dec, 0, outBuf, outOff, length);

        return length;
    }
}
