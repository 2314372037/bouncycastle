package com.android.internal.org.bouncycastle.pqc.crypto.falcon;

class FalconCodec
{

    FalconCodec()
    {
    }

    /* see inner.h */
    int modq_encode(
        byte[] srcout, int out, int max_out_len,
        short[] srcx, int x, int logn)
    {
        int n, out_len, u;
        int buf;
        int acc;
        int acc_len;

        n = 1 << logn;
        for (u = 0; u < n; u++)
        {
            if ((srcx[x + u] & 0x0000ffff) >= 12289)
            {
                return 0;
            }
        }
        out_len = ((n * 14) + 7) >> 3;
        if (srcout == null)
        {
            return out_len;
        }
        if (out_len > max_out_len)
        {
            return 0;
        }
        buf = out;
        acc = 0;
        acc_len = 0;
        for (u = 0; u < n; u++)
        {
            acc = (acc << 14) | (srcx[x + u] & 0xffff);
            acc_len += 14;
            while (acc_len >= 8)
            {
                acc_len -= 8;
                srcout[buf++] = (byte)(acc >> acc_len);
            }
        }
        if (acc_len > 0)
        {
            srcout[buf] = (byte)(acc << (8 - acc_len));
        }
        return out_len;
    }

    /* see inner.h */
    int modq_decode(
        short[] srcx, int x, int logn,
        byte[] srcin, int in, int max_in_len)
    {
        int n, in_len, u;
        int buf;
        int acc;
        int acc_len;

        n = 1 << logn;
        in_len = ((n * 14) + 7) >> 3;
        if (in_len > max_in_len)
        {
            return 0;
        }
        buf = in;
        acc = 0;
        acc_len = 0;
        u = 0;
        while (u < n)
        {
            acc = (acc << 8) | (srcin[buf++] & 0xff);
            acc_len += 8;
            if (acc_len >= 14)
            {
                int w;

                acc_len -= 14;
                w = (acc >>> acc_len) & 0x3FFF;
                if (w >= 12289)
                {
                    return 0;
                }
                srcx[x + u] = (short)w;
                u++;
            }
        }
        if ((acc & ((1 << acc_len) - 1)) != 0)
        {
            return 0;
        }
        return in_len;
    }

    /* see inner.h */
    int trim_i16_encode(
        byte[] srcout, int out, int max_out_len,
        short[] srcx, int x, int logn, int bits)
    {
        int n, u, out_len;
        int minv, maxv;
        int buf;
        int acc, mask;
        int acc_len;

        n = 1 << logn;
        maxv = (1 << (bits - 1)) - 1;
        minv = -maxv;
        for (u = 0; u < n; u++)
        {
            if (srcx[x + u] < minv || srcx[x + u] > maxv)
            {
                return 0;
            }
        }
        out_len = ((n * bits) + 7) >> 3;
        if (srcout == null)
        {
            return out_len;
        }
        if (out_len > max_out_len)
        {
            return 0;
        }
        buf = out;
        acc = 0;
        acc_len = 0;
        mask = (1 << bits) - 1;
        for (u = 0; u < n; u++)
        {
            acc = (acc << bits) | ((srcx[x + u] & 0xfff) & mask);
            acc_len += bits;
            while (acc_len >= 8)
            {
                acc_len -= 8;
                srcout[buf++] = (byte)(acc >> acc_len);
            }
        }
        if (acc_len > 0)
        {
            srcout[buf++] = (byte)(acc << (8 - acc_len));
        }
        return out_len;
    }

    /* see inner.h */
    int trim_i16_decode(
        short[] srcx, int x, int logn, int bits,
        byte[] srcin, int in, int max_in_len)
    {
        int n, in_len;
        int buf;
        int u;
        int acc, mask1, mask2;
        int acc_len;

        n = 1 << logn;
        in_len = ((n * bits) + 7) >> 3;
        if (in_len > max_in_len)
        {
            return 0;
        }
        buf = in;
        u = 0;
        acc = 0;
        acc_len = 0;
        mask1 = (1 << bits) - 1;
        mask2 = 1 << (bits - 1);
        while (u < n)
        {
            acc = (acc << 8) | (srcin[buf++] & 0xff);
            acc_len += 8;
            while (acc_len >= bits && u < n)
            {
                int w;

                acc_len -= bits;
                w = (acc >>> acc_len) & mask1;
                w |= -(w & mask2);
                if (w == -mask2)
                {
                    /*
                     * The -2^(bits-1) value is forbidden.
                     */
                    return 0;
                }
                w |= -(w & mask2);
                srcx[x + u] = (short)w;
                u++;
            }
        }
        if ((acc & ((1 << acc_len) - 1)) != 0)
        {
            /*
             * Extra bits in the last byte must be zero.
             */
            return 0;
        }
        return in_len;
    }

    /* see inner.h */
    int trim_i8_encode(
        byte[] srcout, int out, int max_out_len,
        byte[] srcx, int x, int logn, int bits)
    {
        int n, u, out_len;
        int minv, maxv;
        int buf;
        int acc, mask;
        int acc_len;

        n = 1 << logn;
        maxv = (1 << (bits - 1)) - 1;
        minv = -maxv;
        for (u = 0; u < n; u++)
        {
            if (srcx[x + u] < minv || srcx[x + u] > maxv)
            {
                return 0;
            }
        }
        out_len = ((n * bits) + 7) >> 3;
        if (srcout == null)
        {
            return out_len;
        }
        if (out_len > max_out_len)
        {
            return 0;
        }
        buf = out;
        acc = 0;
        acc_len = 0;
        mask = (1 << bits) - 1;
        for (u = 0; u < n; u++)
        {
            acc = (acc << bits) | ((srcx[x + u] & 0xffff) & mask);
            acc_len += bits;
            while (acc_len >= 8)
            {
                acc_len -= 8;
                srcout[buf++] = (byte)(acc >>> acc_len);
            }
        }
        if (acc_len > 0)
        {
            srcout[buf++] = (byte)(acc << (8 - acc_len));
        }
        return out_len;
    }

    /* see inner.h */
    int trim_i8_decode(
        byte[] srcx, int x, int logn, int bits,
        byte[] srcin, int in, int max_in_len)
    {
        int n, in_len;
        int buf;
        int u;
        int acc, mask1, mask2;
        int acc_len;

        n = 1 << logn;
        in_len = ((n * bits) + 7) >> 3;
        if (in_len > max_in_len)
        {
            return 0;
        }
        buf = in;
        u = 0;
        acc = 0;
        acc_len = 0;
        mask1 = (1 << bits) - 1;
        mask2 = 1 << (bits - 1);
        while (u < n)
        {
            acc = (acc << 8) | (srcin[buf++] & 0xff);
            acc_len += 8;
            while (acc_len >= bits && u < n)
            {
                int w;

                acc_len -= bits;
                w = (acc >>> acc_len) & mask1;
                w |= -(w & mask2);
                if (w == -mask2)
                {
                    /*
                     * The -2^(bits-1) value is forbidden.
                     */
                    return 0;
                }
                srcx[x + u] = (byte)w;
                u++;
            }
        }
        if ((acc & ((1 << acc_len) - 1)) != 0)
        {
            /*
             * Extra bits in the last byte must be zero.
             */
            return 0;
        }
        return in_len;
    }

    /* see inner.h */
    int comp_encode(
        byte[] srcout, int out, int max_out_len,
        short[] srcx, int x, int logn)
    {
        int buf;
        int n, u, v;
        int acc;
        int acc_len;

        n = 1 << logn;
        buf = out;

        /*
         * Make sure that all values are within the -2047..+2047 range.
         */
        for (u = 0; u < n; u++)
        {
            if (srcx[x + u] < -2047 || srcx[x + u] > +2047)
            {
                return 0;
            }
        }

        acc = 0;
        acc_len = 0;
        v = 0;
        for (u = 0; u < n; u++)
        {
            int t;
            int w;

            /*
             * Get sign and absolute value of next integer; push the
             * sign bit.
             */
            acc <<= 1;
            t = srcx[x + u];
            if (t < 0)
            {
                t = -t;
                acc |= 1;
            }
            w = t;

            /*
             * Push the low 7 bits of the absolute value.
             */
            acc <<= 7;
            acc |= w & 127;
            w >>>= 7;

            /*
             * We pushed exactly 8 bits.
             */
            acc_len += 8;

            /*
             * Push as many zeros as necessary, then a one. Since the
             * absolute value is at most 2047, w can only range up to
             * 15 at this point, thus we will add at most 16 bits
             * here. With the 8 bits above and possibly up to 7 bits
             * from previous iterations, we may go up to 31 bits, which
             * will fit in the accumulator, which is an uint32_t.
             */
            acc <<= (w + 1);
            acc |= 1;
            acc_len += w + 1;

            /*
             * Produce all full bytes.
             */
            while (acc_len >= 8)
            {
                acc_len -= 8;
                if (srcout != null)
                {
                    if (v >= max_out_len)
                    {
                        return 0;
                    }
                    srcout[buf + v] = (byte)(acc >>> acc_len);
                }
                v++;
            }
        }

        /*
         * Flush remaining bits (if any).
         */
        if (acc_len > 0)
        {
            if (srcout != null)
            {
                if (v >= max_out_len)
                {
                    return 0;
                }
                srcout[buf + v] = (byte)(acc << (8 - acc_len));
            }
            v++;
        }

        return v;
    }

    /* see inner.h */
    int comp_decode(
        short[] srcx, int x, int logn,
        byte[] srcin, int in, int max_in_len)
    {
        int buf;
        int n, u, v;
        int acc;
        int acc_len;

        n = 1 << logn;
        buf = in;
        acc = 0;
        acc_len = 0;
        v = 0;
        for (u = 0; u < n; u++)
        {
            int b, s, m;

            /*
             * Get next eight bits: sign and low seven bits of the
             * absolute value.
             */
            if (v >= max_in_len)
            {
                return 0;
            }
            acc = (acc << 8) | (srcin[buf + v] & 0xff);
            v++;
            b = acc >>> acc_len;
            s = b & 128;
            m = b & 127;

            /*
             * Get next bits until a 1 is reached.
             */
            for (; ; )
            {
                if (acc_len == 0)
                {
                    if (v >= max_in_len)
                    {
                        return 0;
                    }
                    acc = (acc << 8) | (srcin[buf + v] & 0xff);
                    v++;
                    acc_len = 8;
                }
                acc_len--;
                if (((acc >>> acc_len) & 1) != 0)
                {
                    break;
                }
                m += 128;
                if (m > 2047)
                {
                    return 0;
                }
            }

            /*
             * "-0" is forbidden.
             */
            if (s != 0 && m == 0)
            {
                return 0;
            }

            srcx[x + u] = (short)(s != 0 ? -m : m);
        }

        /*
         * Unused bits in the last byte must be zero.
         */
        if ((acc & ((1 << acc_len) - 1)) != 0)
        {
            return 0;
        }

        return v;
    }

    /*
     * Key elements and signatures are polynomials with small integer
     * coefficients. Here are some statistics gathered over many
     * generated key pairs (10000 or more for each degree):
     *
     *   log(n)     n   max(f,g)   std(f,g)   max(F,G)   std(F,G)
     *      1       2     129       56.31       143       60.02
     *      2       4     123       40.93       160       46.52
     *      3       8      97       28.97       159       38.01
     *      4      16     100       21.48       154       32.50
     *      5      32      71       15.41       151       29.36
     *      6      64      59       11.07       138       27.77
     *      7     128      39        7.91       144       27.00
     *      8     256      32        5.63       148       26.61
     *      9     512      22        4.00       137       26.46
     *     10    1024      15        2.84       146       26.41
     *
     * We want a compact storage format for private key, and, as part of
     * key generation, we are allowed to reject some keys which would
     * otherwise be fine (this does not induce any noticeable vulnerability
     * as long as we reject only a small proportion of possible keys).
     * Hence, we enforce at key generation time maximum values for the
     * elements of f, g, F and G, so that their encoding can be expressed
     * in fixed-width values. Limits have been chosen so that generated
     * keys are almost always within bounds, thus not impacting neither
     * security or performance.
     *
     * IMPORTANT: the code assumes that all coefficients of f, g, F and G
     * ultimately fit in the -127..+127 range. Thus, none of the elements
     * of max_fg_bits[] and max_FG_bits[] shall be greater than 8.
     */

    final byte[] max_fg_bits = {
        0, /* unused */
        8,
        8,
        8,
        8,
        8,
        7,
        7,
        6,
        6,
        5
    };

    final byte[] max_FG_bits = {
        0, /* unused */
        8,
        8,
        8,
        8,
        8,
        8,
        8,
        8,
        8,
        8
    };

    /*
     * When generating a new key pair, we can always reject keys which
     * feature an abnormally large coefficient. This can also be done for
     * signatures, albeit with some care: in case the signature process is
     * used in a derandomized setup (explicitly seeded with the message and
     * private key), we have to follow the specification faithfully, and the
     * specification only enforces a limit on the L2 norm of the signature
     * vector. The limit on the L2 norm implies that the absolute value of
     * a coefficient of the signature cannot be more than the following:
     *
     *   log(n)     n   max sig coeff (theoretical)
     *      1       2       412
     *      2       4       583
     *      3       8       824
     *      4      16      1166
     *      5      32      1649
     *      6      64      2332
     *      7     128      3299
     *      8     256      4665
     *      9     512      6598
     *     10    1024      9331
     *
     * However, the largest observed signature coefficients during our
     * experiments was 1077 (in absolute value), hence we can assume that,
     * with overwhelming probability, signature coefficients will fit
     * in -2047..2047, i.e. 12 bits.
     */

    final byte[] max_sig_bits = {
        0, /* unused */
        10,
        11,
        11,
        12,
        12,
        12,
        12,
        12,
        12,
        12
    };

}
