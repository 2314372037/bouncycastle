package com.android.internal.org.bouncycastle.pkix.jcajce;

import java.io.IOException;
import java.security.cert.Certificate;
import java.security.cert.X509CertSelector;
import java.security.cert.X509Certificate;

import com.android.internal.org.bouncycastle.util.Selector;

/**
 * This class is a Selector implementation for X.509 certificates.
 * 
 * @see com.android.internal.org.bouncycastle.util.Selector
 */
class X509CertStoreSelector
    extends X509CertSelector
    implements Selector
{
    public boolean match(Object obj)
    {
        if (!(obj instanceof X509Certificate))
        {
            return false;
        }

        X509Certificate other = (X509Certificate)obj;

        return super.match(other);
    }

    public boolean match(Certificate cert)
    {
        return match((Object)cert);
    }

    public Object clone()
    {
        X509CertStoreSelector selector = (X509CertStoreSelector)super.clone();

        return selector;
    }

    /**
     * Returns an instance of this from a <code>X509CertSelector</code>.
     *
     * @param selector A <code>X509CertSelector</code> instance.
     * @return An instance of an <code>X509CertStoreSelector</code>.
     * @exception IllegalArgumentException if selector is null or creation fails.
     */
    public static X509CertStoreSelector getInstance(X509CertSelector selector)
    {
        if (selector == null)
        {
            throw new IllegalArgumentException("cannot create from null selector");
        }
        X509CertStoreSelector cs = new X509CertStoreSelector();
        cs.setAuthorityKeyIdentifier(selector.getAuthorityKeyIdentifier());
        cs.setBasicConstraints(selector.getBasicConstraints());
        cs.setCertificate(selector.getCertificate());
        cs.setCertificateValid(selector.getCertificateValid());
        cs.setMatchAllSubjectAltNames(selector.getMatchAllSubjectAltNames());
        try
        {
            cs.setPathToNames(selector.getPathToNames());
            cs.setExtendedKeyUsage(selector.getExtendedKeyUsage());
            cs.setNameConstraints(selector.getNameConstraints());
            cs.setPolicy(selector.getPolicy());
            cs.setSubjectPublicKeyAlgID(selector.getSubjectPublicKeyAlgID());
            cs.setSubjectAlternativeNames(selector.getSubjectAlternativeNames());
        }
        catch (IOException e)
        {
            throw new IllegalArgumentException("error in passed in selector: " + e);
        }
        cs.setIssuer(selector.getIssuer());
        cs.setKeyUsage(selector.getKeyUsage());
        cs.setPrivateKeyValid(selector.getPrivateKeyValid());
        cs.setSerialNumber(selector.getSerialNumber());
        cs.setSubject(selector.getSubject());
        cs.setSubjectKeyIdentifier(selector.getSubjectKeyIdentifier());
        cs.setSubjectPublicKey(selector.getSubjectPublicKey());
        return cs;
    }

}
