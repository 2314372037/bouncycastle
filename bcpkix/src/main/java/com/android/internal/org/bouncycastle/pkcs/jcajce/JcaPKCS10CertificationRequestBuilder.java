package com.android.internal.org.bouncycastle.pkcs.jcajce;

import java.security.PublicKey;

import javax.security.auth.x500.X500Principal;

import com.android.internal.org.bouncycastle.asn1.x500.X500Name;
import com.android.internal.org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import com.android.internal.org.bouncycastle.operator.ContentSigner;
import com.android.internal.org.bouncycastle.pkcs.PKCS10CertificationRequest;
import com.android.internal.org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;

/**
 * Extension of the PKCS#10 builder to support PublicKey and X500Principal objects.
 */
public class JcaPKCS10CertificationRequestBuilder
    extends PKCS10CertificationRequestBuilder
{
    /**
     * Create a PKCS#10 builder for the passed in subject and JCA public key.
     *
     * @param subject an X500Name containing the subject associated with the request we are building.
     * @param publicKey a JCA public key that is to be associated with the request we are building.
     */
    public JcaPKCS10CertificationRequestBuilder(X500Name subject, PublicKey publicKey)
    {
        super(subject, SubjectPublicKeyInfo.getInstance(publicKey.getEncoded()));
    }

    /**
     * Create a PKCS#10 builder for the passed in subject and JCA public key.
     *
     * @param subject an X500Principal containing the subject associated with the request we are building.
     * @param publicKey a JCA public key that is to be associated with the request we are building.
     */
    public JcaPKCS10CertificationRequestBuilder(X500Principal subject, PublicKey publicKey)
    {
        super(X500Name.getInstance(subject.getEncoded()), SubjectPublicKeyInfo.getInstance(publicKey.getEncoded()));
    }

    public PKCS10CertificationRequest build(
          ContentSigner signer,
          PublicKey altPublicKey,
          ContentSigner altSigner)
    {
          return super.build(signer, SubjectPublicKeyInfo.getInstance(altPublicKey.getEncoded()), altSigner);
    }
}
