package com.android.internal.org.bouncycastle.crypto.signers;

import java.security.SecureRandom;

import com.android.internal.org.bouncycastle.crypto.AsymmetricBlockCipher;
import com.android.internal.org.bouncycastle.crypto.CipherParameters;
import com.android.internal.org.bouncycastle.crypto.CryptoException;
import com.android.internal.org.bouncycastle.crypto.CryptoServicesRegistrar;
import com.android.internal.org.bouncycastle.crypto.DataLengthException;
import com.android.internal.org.bouncycastle.crypto.Digest;
import com.android.internal.org.bouncycastle.crypto.Signer;
import com.android.internal.org.bouncycastle.crypto.Xof;
import com.android.internal.org.bouncycastle.crypto.digests.Prehash;
import com.android.internal.org.bouncycastle.crypto.params.ParametersWithRandom;
import com.android.internal.org.bouncycastle.crypto.params.RSABlindingParameters;
import com.android.internal.org.bouncycastle.crypto.params.RSAKeyParameters;
import com.android.internal.org.bouncycastle.util.Arrays;

/**
 * RSA-PSS as described in PKCS# 1 v 2.1.
 * <p>
 * Note: the usual value for the salt length is the number of
 * bytes in the hash function.
 */
public class PSSSigner
    implements Signer
{
    public static final byte TRAILER_IMPLICIT = (byte)0xBC;

    public static PSSSigner createRawSigner(AsymmetricBlockCipher cipher, Digest digest)
    {
        return new PSSSigner(cipher, Prehash.forDigest(digest), digest, digest, digest.getDigestSize(),
            TRAILER_IMPLICIT);
    }

    public static PSSSigner createRawSigner(AsymmetricBlockCipher cipher, Digest contentDigest, Digest mgfDigest,
        int sLen, byte trailer)
    {
        return new PSSSigner(cipher, Prehash.forDigest(contentDigest), contentDigest, mgfDigest, sLen, trailer);
    }

    public static PSSSigner createRawSigner(AsymmetricBlockCipher cipher, Digest contentDigest, Digest mgfDigest,
        byte[] salt, byte trailer)
    {
        return new PSSSigner(cipher, Prehash.forDigest(contentDigest), contentDigest, mgfDigest, salt, trailer);
    }

    private Digest                      contentDigest1;
    private Digest                      contentDigest2;
    private Digest                      mgfDigest;
    private AsymmetricBlockCipher       cipher;
    private SecureRandom                random;

    private int                         hLen;
    private int                         mgfhLen;
    private boolean                     sSet;
    private int                         sLen;
    private int                         emBits;
    private byte[]                      salt;
    private byte[]                      mDash;
    private byte[]                      block;
    private byte                        trailer;

    /**
     * basic constructor
     *
     * @param cipher the asymmetric cipher to use.
     * @param digest the digest to use.
     * @param sLen the length of the salt to use (in bytes).
     */
    public PSSSigner(
        AsymmetricBlockCipher   cipher,
        Digest                  digest,
        int                     sLen)
    {
        this(cipher, digest, sLen, TRAILER_IMPLICIT);
    }

    public PSSSigner(
        AsymmetricBlockCipher   cipher,
        Digest                  contentDigest,
        Digest                  mgfDigest,
        int                     sLen)
    {
        this(cipher, contentDigest, mgfDigest, sLen, TRAILER_IMPLICIT);
    }

    public PSSSigner(
            AsymmetricBlockCipher   cipher,
            Digest                  digest,
            int                     sLen,
            byte                    trailer)
    {
        this(cipher, digest, digest, sLen, trailer);
    }

    public PSSSigner(
        AsymmetricBlockCipher   cipher,
        Digest                  contentDigest,
        Digest                  mgfDigest,
        int                     sLen,
        byte                    trailer)
    {
        this(cipher, contentDigest, contentDigest, mgfDigest, sLen, trailer);
    }

    private PSSSigner(
        AsymmetricBlockCipher   cipher,
        Digest                  contentDigest1,
        Digest                  contentDigest2,
        Digest                  mgfDigest,
        int                     sLen,
        byte                    trailer)
    {
        this.cipher = cipher;
        this.contentDigest1 = contentDigest1;
        this.contentDigest2 = contentDigest2;
        this.mgfDigest = mgfDigest;
        this.hLen = contentDigest2.getDigestSize();
        this.mgfhLen = mgfDigest.getDigestSize();
        this.sSet = false;
        this.sLen = sLen;
        this.salt = new byte[sLen];
        this.mDash = new byte[8 + sLen + hLen];
        this.trailer = trailer;
    }

    public PSSSigner(
        AsymmetricBlockCipher   cipher,
        Digest                  digest,
        byte[]                  salt)
    {
        this(cipher, digest, digest, salt, TRAILER_IMPLICIT);
    }

    public PSSSigner(
        AsymmetricBlockCipher   cipher,
        Digest                  contentDigest,
        Digest                  mgfDigest,
        byte[]                  salt)
    {
        this(cipher, contentDigest, mgfDigest, salt, TRAILER_IMPLICIT);
    }

    public PSSSigner(
        AsymmetricBlockCipher   cipher,
        Digest                  contentDigest,
        Digest                  mgfDigest,
        byte[]                  salt,
        byte                    trailer)
    {
        this(cipher, contentDigest, contentDigest, mgfDigest, salt, trailer);
    }

    private PSSSigner(
        AsymmetricBlockCipher   cipher,
        Digest                  contentDigest1,
        Digest                  contentDigest2,
        Digest                  mgfDigest,
        byte[]                  salt,
        byte                    trailer)
    {
        this.cipher = cipher;
        this.contentDigest1 = contentDigest1;
        this.contentDigest2 = contentDigest2;
        this.mgfDigest = mgfDigest;
        this.hLen = contentDigest2.getDigestSize();
        this.mgfhLen = mgfDigest.getDigestSize();
        this.sSet = true;
        this.sLen = salt.length;
        this.salt = salt;
        this.mDash = new byte[8 + sLen + hLen];
        this.trailer = trailer;
    }

    public void init(
        boolean                 forSigning,
        CipherParameters        param)
    {
        CipherParameters  params;

        if (param instanceof ParametersWithRandom)
        {
            ParametersWithRandom    p = (ParametersWithRandom)param;

            params = p.getParameters();
            random = p.getRandom();
        }
        else
        {
            params = param;
            if (forSigning)
            {
                random = CryptoServicesRegistrar.getSecureRandom();
            }
        }

        RSAKeyParameters kParam;

        if (params instanceof RSABlindingParameters)
        {
            kParam = ((RSABlindingParameters)params).getPublicKey();

            cipher.init(forSigning, param);   // pass on random
        }
        else
        {
            kParam = (RSAKeyParameters)params;

            cipher.init(forSigning, params);
        }
        
        emBits = kParam.getModulus().bitLength() - 1;

        if (emBits < (8 * hLen + 8 * sLen + 9))
        {
            throw new IllegalArgumentException("key too small for specified hash and salt lengths");
        }

        block = new byte[(emBits + 7) / 8];

        reset();
    }

    /**
     * clear possible sensitive data
     */
    private void clearBlock(
        byte[]  block)
    {
        for (int i = 0; i != block.length; i++)
        {
            block[i] = 0;
        }
    }

    /**
     * update the internal digest with the byte b
     */
    public void update(
        byte    b)
    {
        contentDigest1.update(b);
    }

    /**
     * update the internal digest with the byte array in
     */
    public void update(
        byte[]  in,
        int     off,
        int     len)
    {
        contentDigest1.update(in, off, len);
    }

    /**
     * reset the internal state
     */
    public void reset()
    {
        contentDigest1.reset();
    }

    /**
     * generate a signature for the message we've been loaded with using
     * the key we were initialised with.
     */
    public byte[] generateSignature()
        throws CryptoException, DataLengthException
    {
        if (contentDigest1.getDigestSize() != hLen)
        {
            throw new IllegalStateException();
        }

        contentDigest1.doFinal(mDash, mDash.length - hLen - sLen);

        if (sLen != 0)
        {
            if (!sSet)
            {
                random.nextBytes(salt);
            }

            System.arraycopy(salt, 0, mDash, mDash.length - sLen, sLen);
        }

        byte[]  h = new byte[hLen];

        contentDigest2.update(mDash, 0, mDash.length);

        contentDigest2.doFinal(h, 0);

        block[block.length - sLen - 1 - hLen - 1] = 0x01;
        System.arraycopy(salt, 0, block, block.length - sLen - hLen - 1, sLen);

        byte[] dbMask = maskGenerator(h, 0, h.length, block.length - hLen - 1);
        for (int i = 0; i != dbMask.length; i++)
        {
            block[i] ^= dbMask[i];
        }

        System.arraycopy(h, 0, block, block.length - hLen - 1, hLen);

        int firstByteMask = 0xff >>> ((block.length * 8) - emBits);

        block[0] &= firstByteMask;
        block[block.length - 1] = trailer;

        byte[]  b = cipher.processBlock(block, 0, block.length);

        clearBlock(block);

        return b;
    }

    /**
     * return true if the internal state represents the signature described
     * in the passed in array.
     */
    public boolean verifySignature(
        byte[]      signature)
    {
        if (contentDigest1.getDigestSize() != hLen)
        {
            throw new IllegalStateException();
        }

        contentDigest1.doFinal(mDash, mDash.length - hLen - sLen);

        try
        {
            byte[] b = cipher.processBlock(signature, 0, signature.length);
            Arrays.fill(block, 0, block.length - b.length, (byte)0);
            System.arraycopy(b, 0, block, block.length - b.length, b.length);
        }
        catch (Exception e)
        {
            return false;
        }

        int firstByteMask = 0xff >>> ((block.length * 8) - emBits);

        if ((block[0] & 0xff) != (block[0] & firstByteMask)
            || block[block.length - 1] != trailer)
        {
            clearBlock(block);
            return false;
        }

        byte[] dbMask = maskGenerator(block, block.length - hLen - 1, hLen, block.length - hLen - 1);

        for (int i = 0; i != dbMask.length; i++)
        {
            block[i] ^= dbMask[i];
        }

        block[0] &= firstByteMask;

        for (int i = 0; i != block.length - hLen - sLen - 2; i++)
        {
            if (block[i] != 0)
            {
                clearBlock(block);
                return false;
            }
        }

        if (block[block.length - hLen - sLen - 2] != 0x01)
        {
            clearBlock(block);
            return false;
        }

        if (sSet)
        {
            System.arraycopy(salt, 0, mDash, mDash.length - sLen, sLen);
        }
        else
        {
            System.arraycopy(block, block.length - sLen - hLen - 1, mDash, mDash.length - sLen, sLen);
        }

        contentDigest2.update(mDash, 0, mDash.length);
        contentDigest2.doFinal(mDash, mDash.length - hLen);

        for (int i = block.length - hLen - 1, j = mDash.length - hLen;
                                                 j != mDash.length; i++, j++)
        {
            if ((block[i] ^ mDash[j]) != 0)
            {
                clearBlock(mDash);
                clearBlock(block);
                return false;
            }
        }

        clearBlock(mDash);
        clearBlock(block);

        return true;
    }

    /**
     * int to octet string.
     */
    private void ItoOSP(
        int     i,
        byte[]  sp)
    {
        sp[0] = (byte)(i >>> 24);
        sp[1] = (byte)(i >>> 16);
        sp[2] = (byte)(i >>> 8);
        sp[3] = (byte)(i >>> 0);
    }

    private byte[] maskGenerator(
        byte[]  Z,
        int     zOff,
        int     zLen,
        int     length)
    {
        if (mgfDigest instanceof Xof)
        {
            byte[] mask = new byte[length];
            mgfDigest.update(Z, zOff, zLen);
            ((Xof)mgfDigest).doFinal(mask, 0, mask.length);

            return mask;
        }
        else
        {
            return maskGeneratorFunction1(Z, zOff, zLen, length);
        }
    }

    /**
     * mask generator function, as described in PKCS1v2.
     */
    private byte[] maskGeneratorFunction1(
        byte[]  Z,
        int     zOff,
        int     zLen,
        int     length)
    {
        byte[]  mask = new byte[length];
        byte[]  hashBuf = new byte[mgfhLen];
        byte[]  C = new byte[4];
        int     counter = 0;

        mgfDigest.reset();

        while (counter < (length / mgfhLen))
        {
            ItoOSP(counter, C);

            mgfDigest.update(Z, zOff, zLen);
            mgfDigest.update(C, 0, C.length);
            mgfDigest.doFinal(hashBuf, 0);

            System.arraycopy(hashBuf, 0, mask, counter * mgfhLen, mgfhLen);

            counter++;
        }

        if ((counter * mgfhLen) < length)
        {
            ItoOSP(counter, C);

            mgfDigest.update(Z, zOff, zLen);
            mgfDigest.update(C, 0, C.length);
            mgfDigest.doFinal(hashBuf, 0);

            System.arraycopy(hashBuf, 0, mask, counter * mgfhLen, mask.length - (counter * mgfhLen));
        }

        return mask;
    }
}
