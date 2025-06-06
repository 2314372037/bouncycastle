package com.android.internal.org.bouncycastle.operator.jcajce;

import java.security.Key;

import com.android.internal.org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import com.android.internal.org.bouncycastle.operator.GenericKey;

public class JceGenericKey
    extends GenericKey
{
    /**
     * Attempt to simplify the key representation if possible.
     *
     * @param key a provider based key
     * @return the byte encoding if one exists, key object otherwise.
     */
    private static Object getRepresentation(Key key)
    {
        byte[] keyBytes = key.getEncoded();

        if (keyBytes != null)
        {
            return keyBytes;
        }

        return key;
    }

    public JceGenericKey(AlgorithmIdentifier algorithmIdentifier, Key representation)
    {
        super(algorithmIdentifier, getRepresentation(representation));
    }
}
