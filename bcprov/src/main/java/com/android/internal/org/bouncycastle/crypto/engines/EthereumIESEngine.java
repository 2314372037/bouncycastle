package com.android.internal.org.bouncycastle.crypto.engines;


import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.math.BigInteger;

import com.android.internal.org.bouncycastle.crypto.BasicAgreement;
import com.android.internal.org.bouncycastle.crypto.BufferedBlockCipher;
import com.android.internal.org.bouncycastle.crypto.CipherParameters;
import com.android.internal.org.bouncycastle.crypto.DataLengthException;
import com.android.internal.org.bouncycastle.crypto.DerivationFunction;
import com.android.internal.org.bouncycastle.crypto.DerivationParameters;
import com.android.internal.org.bouncycastle.crypto.Digest;
import com.android.internal.org.bouncycastle.crypto.DigestDerivationFunction;
import com.android.internal.org.bouncycastle.crypto.EphemeralKeyPair;
import com.android.internal.org.bouncycastle.crypto.InvalidCipherTextException;
import com.android.internal.org.bouncycastle.crypto.KeyParser;
import com.android.internal.org.bouncycastle.crypto.Mac;
import com.android.internal.org.bouncycastle.crypto.OutputLengthException;
import com.android.internal.org.bouncycastle.crypto.digests.SHA256Digest;
import com.android.internal.org.bouncycastle.crypto.generators.EphemeralKeyPairGenerator;
import com.android.internal.org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import com.android.internal.org.bouncycastle.crypto.params.IESParameters;
import com.android.internal.org.bouncycastle.crypto.params.IESWithCipherParameters;
import com.android.internal.org.bouncycastle.crypto.params.ISO18033KDFParameters;
import com.android.internal.org.bouncycastle.crypto.params.KDFParameters;
import com.android.internal.org.bouncycastle.crypto.params.KeyParameter;
import com.android.internal.org.bouncycastle.crypto.params.ParametersWithIV;
import com.android.internal.org.bouncycastle.util.Arrays;
import com.android.internal.org.bouncycastle.util.BigIntegers;
import com.android.internal.org.bouncycastle.util.Pack;

/**
 * Support class for constructing integrated encryption ciphers for doing basic message exchanges on top of key
 * agreement ciphers. Follows the description given in IEEE Std 1363a.
 * <p>
 * Some tweaks added to IESEngine to conform to the Ethereum encryption approach.
 */
public class EthereumIESEngine
{
    BasicAgreement agree;
    DerivationFunction kdf;
    Mac mac;
    BufferedBlockCipher cipher;
    byte[] macBuf;
    // Ethereum addition: commonMac added when performing the MAC encryption.
    byte[] commonMac;

    boolean forEncryption;
    CipherParameters privParam, pubParam;
    IESParameters param;

    byte[] V;
    private EphemeralKeyPairGenerator keyPairGenerator;
    private KeyParser keyParser;
    private byte[] IV;

    /**
     * Set up for use with stream mode, where the key derivation function is used to provide a stream of bytes to xor with
     * the message.
     *
     * @param agree     the key agreement used as the basis for the encryption
     * @param kdf       the key derivation function used for byte generation
     * @param mac       the message authentication code generator for the message
     * @param commonMac the common MAC bytes to append to the mac
     */
    public EthereumIESEngine(BasicAgreement agree, DerivationFunction kdf, Mac mac, byte[] commonMac)
    {
        this.agree = agree;
        this.kdf = kdf;
        this.mac = mac;
        this.macBuf = new byte[mac.getMacSize()];
        this.commonMac = commonMac;
        this.cipher = null;
    }

    /**
     * Set up for use in conjunction with a block cipher to handle the message. It is <b>strongly</b> recommended that the
     * cipher is not in ECB mode.
     *
     * @param agree     the key agreement used as the basis for the encryption
     * @param kdf       the key derivation function used for byte generation
     * @param mac       the message authentication code generator for the message
     * @param commonMac the common MAC bytes to append to the mac
     * @param cipher    the cipher to used for encrypting the message
     */
    public EthereumIESEngine(BasicAgreement agree, DerivationFunction kdf, Mac mac, byte[] commonMac, BufferedBlockCipher cipher)
    {
        this.agree = agree;
        this.kdf = kdf;
        this.mac = mac;
        this.macBuf = new byte[mac.getMacSize()];
        this.commonMac = commonMac;
        this.cipher = cipher;
    }

    /**
     * Initialise the encryptor.
     *
     * @param forEncryption whether or not this is encryption/decryption.
     * @param privParam     our private key parameters
     * @param pubParam      the recipient's/sender's public key parameters
     * @param params        encoding and derivation parameters, may be wrapped to include an IV for an underlying block cipher.
     */
    public void init(
        boolean forEncryption,
        CipherParameters privParam,
        CipherParameters pubParam,
        CipherParameters params)
    {
        this.forEncryption = forEncryption;
        this.privParam = privParam;
        this.pubParam = pubParam;
        this.V = new byte[0];

        extractParams(params);
    }

    /**
     * Initialise the decryptor.
     *
     * @param publicKey                 the recipient's/sender's public key parameters
     * @param params                    encoding and derivation parameters, may be wrapped to include an IV for an underlying block cipher.
     * @param ephemeralKeyPairGenerator the ephemeral key pair generator to use.
     */
    public void init(
        AsymmetricKeyParameter publicKey,
        CipherParameters params,
        EphemeralKeyPairGenerator ephemeralKeyPairGenerator)
    {
        this.forEncryption = true;
        this.pubParam = publicKey;
        this.keyPairGenerator = ephemeralKeyPairGenerator;

        extractParams(params);
    }

    /**
     * Initialise the encryptor.
     *
     * @param privateKey      the recipient's private key.
     * @param params          encoding and derivation parameters, may be wrapped to include an IV for an underlying block cipher.
     * @param publicKeyParser the parser for reading the ephemeral public key.
     */
    public void init(AsymmetricKeyParameter privateKey, CipherParameters params, KeyParser publicKeyParser)
    {
        this.forEncryption = false;
        this.privParam = privateKey;
        this.keyParser = publicKeyParser;

        extractParams(params);
    }

    private void extractParams(CipherParameters params)
    {
        if (params instanceof ParametersWithIV)
        {
            this.IV = ((ParametersWithIV)params).getIV();
            this.param = (IESParameters)((ParametersWithIV)params).getParameters();
        }
        else
        {
            this.IV = null;
            this.param = (IESParameters)params;
        }
    }

    public BufferedBlockCipher getCipher()
    {
        return cipher;
    }

    public Mac getMac()
    {
        return mac;
    }

    private byte[] encryptBlock(byte[] in, int inOff, int inLen)
        throws InvalidCipherTextException
    {
        byte[] C = null, K = null, K1 = null, K2 = null;
        int len;

        if (cipher == null)
        {
            // Streaming mode.
            K1 = new byte[inLen];
            K2 = new byte[param.getMacKeySize() / 8];
            K = new byte[K1.length + K2.length];

            kdf.generateBytes(K, 0, K.length);

            if (V.length != 0)
            {
                System.arraycopy(K, 0, K2, 0, K2.length);
                System.arraycopy(K, K2.length, K1, 0, K1.length);
            }
            else
            {
                System.arraycopy(K, 0, K1, 0, K1.length);
                System.arraycopy(K, inLen, K2, 0, K2.length);
            }

            C = new byte[inLen];

            for (int i = 0; i != inLen; i++)
            {
                C[i] = (byte)(in[inOff + i] ^ K1[i]);
            }
            len = inLen;
        }
        else
        {
            // Block cipher mode.
            K1 = new byte[((IESWithCipherParameters)param).getCipherKeySize() / 8];
            K2 = new byte[param.getMacKeySize() / 8];
            K = new byte[K1.length + K2.length];

            kdf.generateBytes(K, 0, K.length);
            System.arraycopy(K, 0, K1, 0, K1.length);
            System.arraycopy(K, K1.length, K2, 0, K2.length);

            // If iv provided use it to initialise the cipher
            if (IV != null)
            {
                cipher.init(true, new ParametersWithIV(new KeyParameter(K1), IV));
            }
            else
            {
                cipher.init(true, new KeyParameter(K1));
            }

            C = new byte[cipher.getOutputSize(inLen)];
            len = cipher.processBytes(in, inOff, inLen, C, 0);
            len += cipher.doFinal(C, len);
        }


        // Convert the length of the encoding vector into a byte array.
        byte[] P2 = param.getEncodingV();
        byte[] L2 = null;
        if (V.length != 0)
        {
            L2 = getLengthTag(P2);
        }


        // Apply the MAC.
        byte[] T = new byte[mac.getMacSize()];
        // Ethereum change:
        // Instead of initializing the mac with the bytes, we initialize with the hash of the bytes.
        // Old code: mac.init(new KeyParameter(K2));
        Digest hash = SHA256Digest.newInstance();
        byte[] K2hash = new byte[hash.getDigestSize()];
        hash.reset();
        hash.update(K2, 0, K2.length);
        hash.doFinal(K2hash, 0);

        mac.init(new KeyParameter(K2hash));
        // we also update the mac with the IV:
        mac.update(IV, 0, IV.length);
        // end of Ethereum change.
        mac.update(C, 0, C.length);
        if (P2 != null)
        {
            mac.update(P2, 0, P2.length);
        }
        if (V.length != 0)
        {
            mac.update(L2, 0, L2.length);
        }
        // Ethereum change
        mac.update(commonMac, 0, commonMac.length);
        mac.doFinal(T, 0);


        // Output the triple (V,C,T).
        byte[] Output = new byte[V.length + len + T.length];
        System.arraycopy(V, 0, Output, 0, V.length);
        System.arraycopy(C, 0, Output, V.length, len);
        System.arraycopy(T, 0, Output, V.length + len, T.length);
        return Output;
    }

    private byte[] decryptBlock(byte[] in_enc, int inOff, int inLen)
        throws InvalidCipherTextException
    {
        byte[] M, K, K1, K2;
        int len = 0;

        // Ensure that the length of the input is greater than the MAC in bytes
        if (inLen < V.length + mac.getMacSize())
        {
            throw new InvalidCipherTextException("length of input must be greater than the MAC and V combined");
        }

        // note order is important: set up keys, do simple encryptions, check mac, do final encryption.
        if (cipher == null)
        {
            // Streaming mode.
            K1 = new byte[inLen - V.length - mac.getMacSize()];
            K2 = new byte[param.getMacKeySize() / 8];
            K = new byte[K1.length + K2.length];

            kdf.generateBytes(K, 0, K.length);

            if (V.length != 0)
            {
                System.arraycopy(K, 0, K2, 0, K2.length);
                System.arraycopy(K, K2.length, K1, 0, K1.length);
            }
            else
            {
                System.arraycopy(K, 0, K1, 0, K1.length);
                System.arraycopy(K, K1.length, K2, 0, K2.length);
            }

            // process the message
            M = new byte[K1.length];

            for (int i = 0; i != K1.length; i++)
            {
                M[i] = (byte)(in_enc[inOff + V.length + i] ^ K1[i]);
            }
        }
        else
        {
            // Block cipher mode.
            K1 = new byte[((IESWithCipherParameters)param).getCipherKeySize() / 8];
            K2 = new byte[param.getMacKeySize() / 8];
            K = new byte[K1.length + K2.length];

            kdf.generateBytes(K, 0, K.length);
            System.arraycopy(K, 0, K1, 0, K1.length);
            System.arraycopy(K, K1.length, K2, 0, K2.length);

            CipherParameters cp = new KeyParameter(K1);

            // If IV provide use it to initialize the cipher
            if (IV != null)
            {
                cp = new ParametersWithIV(cp, IV);
            }

            cipher.init(false, cp);

            M = new byte[cipher.getOutputSize(inLen - V.length - mac.getMacSize())];

            // do initial processing
            len = cipher.processBytes(in_enc, inOff + V.length, inLen - V.length - mac.getMacSize(), M, 0);
        }

        // Convert the length of the encoding vector into a byte array.
        byte[] P2 = param.getEncodingV();
        byte[] L2 = null;
        if (V.length != 0)
        {
            L2 = getLengthTag(P2);
        }

        // Verify the MAC.
        int end = inOff + inLen;
        byte[] T1 = Arrays.copyOfRange(in_enc, end - mac.getMacSize(), end);

        byte[] T2 = new byte[T1.length];
        // Ethereum change:
        // Instead of initializing the mac with the bytes, we initialize with the hash of the bytes.
        // Old code: mac.init(new KeyParameter(K2));
        Digest hash = SHA256Digest.newInstance();
        byte[] K2hash = new byte[hash.getDigestSize()];
        hash.reset();
        hash.update(K2, 0, K2.length);
        hash.doFinal(K2hash, 0);
        mac.init(new KeyParameter(K2hash));
        // we also update the mac with the IV:
        mac.update(IV, 0, IV.length);
        // end of Ethereum change.

        mac.update(in_enc, inOff + V.length, inLen - V.length - T2.length);

        if (P2 != null)
        {
            mac.update(P2, 0, P2.length);
        }
        if (V.length != 0)
        {
            mac.update(L2, 0, L2.length);
        }
        // Ethereum change
        mac.update(commonMac, 0, commonMac.length);
        mac.doFinal(T2, 0);

        if (!Arrays.constantTimeAreEqual(T1, T2))
        {
            throw new InvalidCipherTextException("invalid MAC");
        }

        if (cipher == null)
        {
            return M;
        }
        else
        {
            len += cipher.doFinal(M, len);

            return Arrays.copyOfRange(M, 0, len);
        }
    }


    public byte[] processBlock(byte[] in, int inOff, int inLen)
        throws InvalidCipherTextException
    {
        if (forEncryption)
        {
            if (keyPairGenerator != null)
            {
                EphemeralKeyPair ephKeyPair = keyPairGenerator.generate();

                this.privParam = ephKeyPair.getKeyPair().getPrivate();
                this.V = ephKeyPair.getEncodedPublicKey();
            }
        }
        else
        {
            if (keyParser != null)
            {
                ByteArrayInputStream bIn = new ByteArrayInputStream(in, inOff, inLen);

                try
                {
                    this.pubParam = keyParser.readKey(bIn);
                }
                catch (IOException e)
                {
                    throw new InvalidCipherTextException("unable to recover ephemeral public key: " + e.getMessage(), e);
                }
                catch (IllegalArgumentException e)
                {
                    throw new InvalidCipherTextException("unable to recover ephemeral public key: " + e.getMessage(), e);
                }

                int encLength = (inLen - bIn.available());
                this.V = Arrays.copyOfRange(in, inOff, inOff + encLength);
            }
        }

        // Compute the common value and convert to byte array.
        agree.init(privParam);
        BigInteger z = agree.calculateAgreement(pubParam);
        byte[] Z = BigIntegers.asUnsignedByteArray(agree.getFieldSize(), z);

        // Create input to KDF.
        if (V.length != 0)
        {
            byte[] VZ = Arrays.concatenate(V, Z);
            Arrays.fill(Z, (byte)0);
            Z = VZ;
        }

        try
        {
            // Initialise the KDF.
            KDFParameters kdfParam = new KDFParameters(Z, param.getDerivationV());
            kdf.init(kdfParam);

            return forEncryption ? encryptBlock(in, inOff, inLen) : decryptBlock(in, inOff, inLen);
        }
        finally
        {
            Arrays.fill(Z, (byte)0);
        }
    }

    // as described in Shroup's paper and P1363a
    protected byte[] getLengthTag(byte[] p2)
    {
        byte[] L2 = new byte[8];
        if (p2 != null)
        {
            Pack.longToBigEndian(p2.length * 8L, L2, 0);
        }
        return L2;
    }

    /**
     * Basic KDF generator for derived keys and ivs as defined by IEEE P1363a/ISO 18033 <br>
     * This implementation is based on ISO 18033/P1363a.
     * <p>
     * This class has been adapted from the <tt>BaseKDFBytesGenerator</tt> implementation of Bouncy Castle. Only one
     * change is present specifically for Ethereum.
     */
    public static class HandshakeKDFFunction
        implements DigestDerivationFunction
    {
        private int counterStart;
        private Digest digest;
        private byte[] shared;
        private byte[] iv;

        /**
         * Construct a KDF Parameters generator.
         * <p>
         *
         * @param counterStart value of counter.
         * @param digest       the digest to be used as the source of derived keys.
         */
        public HandshakeKDFFunction(int counterStart, Digest digest)
        {
            this.counterStart = counterStart;
            this.digest = digest;
        }

        public void init(DerivationParameters param)
        {
            if (param instanceof KDFParameters)
            {
                KDFParameters p = (KDFParameters)param;

                shared = p.getSharedSecret();
                iv = p.getIV();
            }
            else if (param instanceof ISO18033KDFParameters)
            {
                ISO18033KDFParameters p = (ISO18033KDFParameters)param;

                shared = p.getSeed();
                iv = null;
            }
            else
            {
                throw new IllegalArgumentException("KDF parameters required for generator");
            }
        }

        /**
         * return the underlying digest.
         */
        public Digest getDigest()
        {
            return digest;
        }

        /**
         * fill len bytes of the output buffer with bytes generated from the derivation function.
         *
         * @throws IllegalArgumentException if the size of the request will cause an overflow.
         * @throws DataLengthException if the out buffer is too small.
         */
        public int generateBytes(byte[] out, int outOff, int len)
            throws DataLengthException, IllegalArgumentException
        {
            if ((out.length - len) < outOff)
            {
                throw new OutputLengthException("output buffer too small");
            }

            long oBytes = len;
            int outLen = digest.getDigestSize();

            //
            // this is at odds with the standard implementation, the
            // maximum value should be hBits * (2^32 - 1) where hBits
            // is the digest output size in bits. We can't have an
            // array with a long index at the moment...
            //
            if (oBytes > ((2L << 32) - 1))
            {
                throw new IllegalArgumentException("output length too large");
            }

            int cThreshold = (int)((oBytes + outLen - 1) / outLen);

            byte[] dig = new byte[digest.getDigestSize()];

            byte[] C = new byte[4];
            Pack.intToBigEndian(counterStart, C, 0);

            int counterBase = counterStart & ~0xFF;

            for (int i = 0; i < cThreshold; i++)
            {
                // only change for Ethereum: invert those 2 lines.
                digest.update(C, 0, C.length);
                digest.update(shared, 0, shared.length);
                // End of change for Ethereum.

                if (iv != null)
                {
                    digest.update(iv, 0, iv.length);
                }

                digest.doFinal(dig, 0);

                if (len > outLen)
                {
                    System.arraycopy(dig, 0, out, outOff, outLen);
                    outOff += outLen;
                    len -= outLen;
                }
                else
                {
                    System.arraycopy(dig, 0, out, outOff, len);
                }

                if (++C[3] == 0)
                {
                    counterBase += 0x100;
                    Pack.intToBigEndian(counterBase, C, 0);
                }
            }

            digest.reset();

            return (int)oBytes;
        }
    }
}
