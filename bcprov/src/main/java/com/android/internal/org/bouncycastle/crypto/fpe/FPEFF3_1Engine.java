package com.android.internal.org.bouncycastle.crypto.fpe;

import com.android.internal.org.bouncycastle.crypto.BlockCipher;
import com.android.internal.org.bouncycastle.crypto.CipherParameters;
import com.android.internal.org.bouncycastle.crypto.engines.AESEngine;
import com.android.internal.org.bouncycastle.crypto.params.FPEParameters;
import com.android.internal.org.bouncycastle.util.Properties;

/**
 * NIST SP 800-38G, FF3-1 format preserving encryption.
 */
public class FPEFF3_1Engine
    extends FPEEngine
{

    /**
     * Base constructor - the engine will use AES.
     */
    public FPEFF3_1Engine()
    {
        this(AESEngine.newInstance());
    }

    /**
     * Build the engine using the specified 128 bit block cipher.
     *
     * @param baseCipher cipher to base the FPE algorithm on.
     */
    public FPEFF3_1Engine(BlockCipher baseCipher)
    {
        super(baseCipher);

        if (baseCipher.getBlockSize() != 16)
        {
            throw new IllegalArgumentException("base cipher needs to be 128 bits");
        }

        if (Properties.isOverrideSet(SP80038G.FPE_DISABLED))
        {
            throw new UnsupportedOperationException("FPE disabled");
        }
    }

    public void init(boolean forEncryption, CipherParameters parameters)
    {
        this.forEncryption = forEncryption;

        this.fpeParameters = (FPEParameters)parameters;

        baseCipher.init(!fpeParameters.isUsingInverseFunction(), fpeParameters.getKey().reverse());

        if (fpeParameters.getTweak().length != 7)
        {
            throw new IllegalArgumentException("tweak should be 56 bits");
        }
    }

    public String getAlgorithmName()
    {
        return "FF3-1";
    }

    protected int encryptBlock(byte[] inBuf, int inOff, int length, byte[] outBuf, int outOff)
    {
        byte[] enc;

        if (fpeParameters.getRadix() > 256)
        {
            enc = toByteArray(SP80038G.encryptFF3_1w(baseCipher, fpeParameters.getRadixConverter(), fpeParameters.getTweak(), toShortArray(inBuf), inOff, length / 2));
        }
        else
        {
            enc = SP80038G.encryptFF3_1(baseCipher, fpeParameters.getRadixConverter(), fpeParameters.getTweak(), inBuf, inOff, length);
        }

        System.arraycopy(enc, 0, outBuf, outOff, length);

        return length;
    }

    protected int decryptBlock(byte[] inBuf, int inOff, int length, byte[] outBuf, int outOff)
    {
        byte[] dec;

        if (fpeParameters.getRadix() > 256)
        {
            dec = toByteArray(SP80038G.decryptFF3_1w(baseCipher, fpeParameters.getRadixConverter(), fpeParameters.getTweak(), toShortArray(inBuf), inOff, length / 2));
        }
        else
        {
            dec = SP80038G.decryptFF3_1(baseCipher, fpeParameters.getRadixConverter(), fpeParameters.getTweak(), inBuf, inOff, length);
        }

        System.arraycopy(dec, 0, outBuf, outOff, length);

        return length;
    }
}
