package com.android.internal.org.bouncycastle.pqc.crypto.xwing;

import com.android.internal.org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import com.android.internal.org.bouncycastle.crypto.params.X25519PublicKeyParameters;
import com.android.internal.org.bouncycastle.pqc.crypto.crystals.kyber.KyberParameters;
import com.android.internal.org.bouncycastle.pqc.crypto.crystals.kyber.KyberPublicKeyParameters;
import com.android.internal.org.bouncycastle.util.Arrays;

public class XWingPublicKeyParameters
    extends XWingKeyParameters
{
    private final KyberPublicKeyParameters kybPub;
    private final X25519PublicKeyParameters xdhPub;

    XWingPublicKeyParameters(AsymmetricKeyParameter kybPub, AsymmetricKeyParameter xdhPub)
    {
        super(false);

        this.kybPub = (KyberPublicKeyParameters)kybPub;
        this.xdhPub = (X25519PublicKeyParameters)xdhPub;
    }

    public XWingPublicKeyParameters(byte[] encoding)
    {
        super(false);

        this.kybPub = new KyberPublicKeyParameters(KyberParameters.kyber768, Arrays.copyOfRange(encoding, 0, encoding.length - X25519PublicKeyParameters.KEY_SIZE));
        this.xdhPub = new X25519PublicKeyParameters(encoding, encoding.length - X25519PublicKeyParameters.KEY_SIZE);
    }

    KyberPublicKeyParameters getKyberPublicKey()
    {
        return kybPub;
    }

    X25519PublicKeyParameters getXDHPublicKey()
    {
        return xdhPub;
    }

    public byte[] getEncoded()
    {
        return Arrays.concatenate(kybPub.getEncoded(), xdhPub.getEncoded());
    }
}
