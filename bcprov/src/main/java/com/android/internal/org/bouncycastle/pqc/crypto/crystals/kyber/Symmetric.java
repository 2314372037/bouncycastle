package com.android.internal.org.bouncycastle.pqc.crypto.crystals.kyber;

import com.android.internal.org.bouncycastle.crypto.ExtendedDigest;
import com.android.internal.org.bouncycastle.crypto.StreamCipher;
import com.android.internal.org.bouncycastle.crypto.digests.SHA256Digest;
import com.android.internal.org.bouncycastle.crypto.digests.SHA3Digest;
import com.android.internal.org.bouncycastle.crypto.digests.SHA512Digest;
import com.android.internal.org.bouncycastle.crypto.digests.SHAKEDigest;
import com.android.internal.org.bouncycastle.crypto.engines.AESEngine;
import com.android.internal.org.bouncycastle.crypto.modes.SICBlockCipher;
import com.android.internal.org.bouncycastle.crypto.params.KeyParameter;
import com.android.internal.org.bouncycastle.crypto.params.ParametersWithIV;

abstract class Symmetric
{

    final int xofBlockBytes;

    abstract void hash_h(byte[] out, byte[] in, int outOffset);

    abstract void hash_g(byte[] out, byte[] in);

    abstract void xofAbsorb(byte[] seed, byte x, byte y);

    abstract void xofSqueezeBlocks(byte[] out, int outOffset, int outLen);

    abstract void prf(byte[] out, byte[] key, byte nonce);

    abstract void kdf(byte[] out, byte[] in);

    Symmetric(int blockBytes)
    {
        this.xofBlockBytes = blockBytes;
    }


    static class ShakeSymmetric
        extends Symmetric
    {
        private final SHAKEDigest xof;
        private final SHA3Digest sha3Digest512;
        private final SHA3Digest sha3Digest256;
        private final SHAKEDigest shakeDigest;

        ShakeSymmetric()
        {
            super(168);
            this.xof = new SHAKEDigest(128);
            this.shakeDigest = new SHAKEDigest(256);
            this.sha3Digest256 = new SHA3Digest(256);
            this.sha3Digest512 = new SHA3Digest(512);
        }

        @Override
        void hash_h(byte[] out, byte[] in, int outOffset)
        {
            sha3Digest256.update(in, 0, in.length);
            sha3Digest256.doFinal(out, outOffset);
        }

        @Override
        void hash_g(byte[] out, byte[] in)
        {
            sha3Digest512.update(in, 0, in.length);
            sha3Digest512.doFinal(out, 0);
        }

        @Override
        void xofAbsorb(byte[] seed, byte a, byte b)
        {
            xof.reset();
            byte[] buf = new byte[seed.length + 2];
            System.arraycopy(seed, 0, buf, 0, seed.length);
            buf[seed.length] = a;
            buf[seed.length + 1] = b;
            xof.update(buf, 0, seed.length + 2);
        }

        @Override
        void xofSqueezeBlocks(byte[] out, int outOffset, int outLen)
        {
            xof.doOutput(out, outOffset, outLen);
        }

        @Override
        void prf(byte[] out, byte[] seed, byte nonce)
        {
            byte[] extSeed = new byte[seed.length + 1];
            System.arraycopy(seed, 0, extSeed, 0, seed.length);
            extSeed[seed.length] = nonce;
            shakeDigest.update(extSeed, 0, extSeed.length);
            shakeDigest.doFinal(out, 0, out.length);
        }

        @Override
        void kdf(byte[] out, byte[] in)
        {
            shakeDigest.update(in, 0, in.length);
            shakeDigest.doFinal(out, 0, out.length);
        }
    }

    /**
     * @deprecated
     * obsolete to be removed
     */
    @Deprecated
    static class AesSymmetric
        extends Symmetric
    {
        private final SHA256Digest sha256Digest;
        private final SHA512Digest sha512Digest;
        private final StreamCipher cipher;

        AesSymmetric()
        {
            super(64);
            this.sha256Digest = new SHA256Digest();
            this.sha512Digest = new SHA512Digest();
            this.cipher = SICBlockCipher.newInstance(AESEngine.newInstance());
        }

        private void doDigest(ExtendedDigest digest, byte[] out, byte[] in, int outOffset)
        {
            digest.update(in, 0, in.length);
            digest.doFinal(out, outOffset);
        }

        private void aes128(byte[] out, int offset, int size)
        {
            byte[] buf = new byte[size];   // TODO: there might be a more efficient way of doing this...
            cipher.processBytes(buf, 0, size, out, offset);
        }

        @Override
        void hash_h(byte[] out, byte[] in, int outOffset)
        {
            doDigest(sha256Digest, out, in, outOffset);
        }

        @Override
        void hash_g(byte[] out, byte[] in)
        {
            doDigest(sha512Digest, out, in, 0);
        }

        @Override
        void xofAbsorb(byte[] key, byte x, byte y)
        {
            byte[] expnonce = new byte[12];
            expnonce[0] = x;
            expnonce[1] = y;

            ParametersWithIV kp = new ParametersWithIV(new KeyParameter(key, 0, 32), expnonce);
            cipher.init(true, kp);
        }

        @Override
        void xofSqueezeBlocks(byte[] out, int outOffset, int outLen)
        {
            aes128(out, outOffset, outLen);
        }

        @Override
        void prf(byte[] out, byte[] key, byte nonce)
        {
            byte[] expnonce = new byte[12];
            expnonce[0] = nonce;

            ParametersWithIV kp = new ParametersWithIV(new KeyParameter(key, 0, 32), expnonce);
            cipher.init(true, kp);
            aes128(out, 0, out.length);
        }

        @Override
        void kdf(byte[] out, byte[] in)
        {
            byte[] buf = new byte[32];
            doDigest(sha256Digest, buf, in, 0);
            System.arraycopy(buf, 0, out, 0, out.length);
        }
    }
}
