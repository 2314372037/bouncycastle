package com.android.internal.org.bouncycastle.pqc.crypto;

import com.android.internal.org.bouncycastle.crypto.params.AsymmetricKeyParameter;

/**
 * Interface for NewHope style key material exchange generators.
 */
public interface ExchangePairGenerator
{
    /**
     * Generate an exchange pair based on the sender public key.
     *
     * @param senderPublicKey the public key of the exchange initiator.
     * @return An ExchangePair derived from the sender public key.
     */
    ExchangePair generateExchange(AsymmetricKeyParameter senderPublicKey);
}
