package com.android.internal.org.bouncycastle.crypto.commitments;

import java.security.SecureRandom;

import com.android.internal.org.bouncycastle.crypto.Commitment;
import com.android.internal.org.bouncycastle.crypto.Committer;
import com.android.internal.org.bouncycastle.crypto.DataLengthException;
import com.android.internal.org.bouncycastle.crypto.Digest;
import com.android.internal.org.bouncycastle.crypto.ExtendedDigest;
import com.android.internal.org.bouncycastle.util.Arrays;

/**
 * A basic hash-committer based on the one described in "Making Mix Nets Robust for Electronic Voting by Randomized Partial Checking",
 * by Jakobsson, Juels, and Rivest (11th Usenix Security Symposium, 2002).
 * <p>
 * The algorithm used by this class differs from the one given in that it includes the length of the message in the hash calculation.
 * </p>
 */
public class GeneralHashCommitter
    implements Committer
{
    private final Digest digest;
    private final int byteLength;
    private final SecureRandom random;

    /**
     * Base Constructor. The maximum message length that can be committed to is half the length of the internal
     * block size for the digest (ExtendedDigest.getBlockLength()).
     *
     * @param digest digest to use for creating commitments.
     * @param random source of randomness for generating secrets.
     */
    public GeneralHashCommitter(ExtendedDigest digest, SecureRandom random)
    {
        this.digest = digest;
        this.byteLength = digest.getByteLength();
        this.random = random;
    }

    /**
     * Generate a commitment for the passed in message.
     *
     * @param message the message to be committed to,
     * @return a Commitment
     */
    public Commitment commit(byte[] message)
    {
        if (message.length > byteLength / 2)
        {
            throw new DataLengthException("Message to be committed to too large for digest.");
        }

        byte[] w = new byte[byteLength - message.length];

        random.nextBytes(w);

        return new Commitment(w, calculateCommitment(w, message));
    }

    /**
     * Return true if the passed in commitment represents a commitment to the passed in message.
     *
     * @param commitment a commitment previously generated.
     * @param message the message that was expected to have been committed to.
     * @return true if commitment matches message, false otherwise.
     */
    public boolean isRevealed(Commitment commitment, byte[] message)
    {
        if (message.length + commitment.getSecret().length != byteLength)
        {
            throw new DataLengthException("Message and witness secret lengths do not match.");
        }

        byte[] calcCommitment = calculateCommitment(commitment.getSecret(), message);

        return Arrays.constantTimeAreEqual(commitment.getCommitment(), calcCommitment);
    }

    private byte[] calculateCommitment(byte[] w, byte[] message)
    {
        byte[] commitment = new byte[digest.getDigestSize()];

        digest.update(w, 0, w.length);
        digest.update(message, 0, message.length);

        digest.update((byte)((message.length >>> 8)));
        digest.update((byte)(message.length));

        digest.doFinal(commitment, 0);

        return commitment;
    }
}
