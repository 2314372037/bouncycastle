package com.android.internal.org.bouncycastle.its;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

import com.android.internal.org.bouncycastle.asn1.ASN1Encodable;
import com.android.internal.org.bouncycastle.its.operator.ECDSAEncoder;
import com.android.internal.org.bouncycastle.its.operator.ITSContentVerifierProvider;
import com.android.internal.org.bouncycastle.oer.Element;
import com.android.internal.org.bouncycastle.oer.OEREncoder;
import com.android.internal.org.bouncycastle.oer.OERInputStream;
import com.android.internal.org.bouncycastle.oer.its.etsi103097.EtsiTs103097DataSigned;
import com.android.internal.org.bouncycastle.oer.its.ieee1609dot2.Ieee1609Dot2Content;
import com.android.internal.org.bouncycastle.oer.its.ieee1609dot2.Opaque;
import com.android.internal.org.bouncycastle.oer.its.ieee1609dot2.SignedData;
import com.android.internal.org.bouncycastle.oer.its.ieee1609dot2.basetypes.Signature;
import com.android.internal.org.bouncycastle.oer.its.template.etsi103097.EtsiTs103097Module;
import com.android.internal.org.bouncycastle.oer.its.template.ieee1609dot2.IEEE1609dot2;
import com.android.internal.org.bouncycastle.operator.ContentVerifier;

public class ETSISignedData
{
    private final SignedData signedData;

    private static final Element oerDef = EtsiTs103097Module.EtsiTs103097Data_Signed.build();

    public ETSISignedData(Opaque opaque)
        throws IOException
    {
        this(opaque.getInputStream());
    }

    public ETSISignedData(byte[] oerEncoded)
        throws IOException
    {
        this(new ByteArrayInputStream(oerEncoded));
    }

    public ETSISignedData(InputStream str)
        throws IOException
    {
        OERInputStream oerIn;
        if (str instanceof OERInputStream)
        {
            oerIn = (OERInputStream)str;
        }
        else
        {
            oerIn = new OERInputStream(str);
        }
        ASN1Encodable asn1 = oerIn.parse(oerDef);

        Ieee1609Dot2Content content = EtsiTs103097DataSigned.getInstance(asn1).getContent();
        if (content.getChoice() != Ieee1609Dot2Content.signedData)
        {
            throw new IllegalStateException("EtsiTs103097Data-Signed did not have signed data content");
        }
        this.signedData = SignedData.getInstance(content.getIeee1609Dot2Content());

    }

    public ETSISignedData(EtsiTs103097DataSigned etsiTs103097Data_signed)
    {
        Ieee1609Dot2Content content = etsiTs103097Data_signed.getContent();
        if (content.getChoice() != Ieee1609Dot2Content.signedData)
        {
            throw new IllegalStateException("EtsiTs103097Data-Signed did not have signed data content");
        }
        this.signedData = SignedData.getInstance(etsiTs103097Data_signed.getContent());
    }

    public ETSISignedData(SignedData signedData)
    {
        this.signedData = signedData;
    }

    /**
     * Verify signature is valid with respect to the supplied public key.
     * Contextual verification, ie "is this SignedData what you are expecting?" type checking needs to be done
     * by the caller.
     *
     * @return true if the signature was valid.
     * @throws Exception
     */
    public boolean signatureValid(ITSContentVerifierProvider verifierProvider)
        throws Exception
    {
        Signature sig = signedData.getSignature();
        ContentVerifier verifier = verifierProvider.get(sig.getChoice());
        OutputStream os = verifier.getOutputStream();
        os.write(OEREncoder.toByteArray(signedData.getTbsData(), IEEE1609dot2.ToBeSignedData.build()));
        os.close();

        return verifier.verify(ECDSAEncoder.toX962(signedData.getSignature()));

    }

    public byte[] getEncoded()
    {
        return OEREncoder.toByteArray(new EtsiTs103097DataSigned(
            Ieee1609Dot2Content
                .signedData(signedData)
        ), EtsiTs103097Module.EtsiTs103097Data_Signed.build());
    }

    public SignedData getSignedData()
    {
        return signedData;
    }
}
