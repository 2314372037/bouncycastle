package com.android.internal.org.bouncycastle.openssl.jcajce;

import java.io.IOException;
import java.io.InputStream;
import java.security.AlgorithmParameters;
import java.security.GeneralSecurityException;
import java.security.Provider;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;

import com.android.internal.org.bouncycastle.asn1.pkcs.EncryptionScheme;
import com.android.internal.org.bouncycastle.asn1.pkcs.KeyDerivationFunc;
import com.android.internal.org.bouncycastle.asn1.pkcs.PBEParameter;
import com.android.internal.org.bouncycastle.asn1.pkcs.PBES2Parameters;
import com.android.internal.org.bouncycastle.asn1.pkcs.PBKDF2Params;
import com.android.internal.org.bouncycastle.asn1.pkcs.PKCS12PBEParams;
import com.android.internal.org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import com.android.internal.org.bouncycastle.crypto.CharToByteConverter;
import com.android.internal.org.bouncycastle.jcajce.PBKDF1KeyWithParameters;
import com.android.internal.org.bouncycastle.jcajce.PKCS12KeyWithParameters;
import com.android.internal.org.bouncycastle.jcajce.io.CipherInputStream;
import com.android.internal.org.bouncycastle.jcajce.util.DefaultJcaJceHelper;
import com.android.internal.org.bouncycastle.jcajce.util.JcaJceHelper;
import com.android.internal.org.bouncycastle.jcajce.util.NamedJcaJceHelper;
import com.android.internal.org.bouncycastle.jcajce.util.ProviderJcaJceHelper;
import com.android.internal.org.bouncycastle.openssl.PEMException;
import com.android.internal.org.bouncycastle.operator.InputDecryptor;
import com.android.internal.org.bouncycastle.operator.InputDecryptorProvider;
import com.android.internal.org.bouncycastle.operator.OperatorCreationException;
import com.android.internal.org.bouncycastle.util.Strings;

/**
 * DecryptorProviderBuilder for producing DecryptorProvider for use with PKCS8EncryptedPrivateKeyInfo.
 */
public class JceOpenSSLPKCS8DecryptorProviderBuilder
{
    private JcaJceHelper helper;

    public JceOpenSSLPKCS8DecryptorProviderBuilder()
    {
        helper = new DefaultJcaJceHelper();
    }

    public JceOpenSSLPKCS8DecryptorProviderBuilder setProvider(String providerName)
    {
        helper = new NamedJcaJceHelper(providerName);

        return this;
    }

    public JceOpenSSLPKCS8DecryptorProviderBuilder setProvider(Provider provider)
    {
        helper = new ProviderJcaJceHelper(provider);

        return this;
    }

    public InputDecryptorProvider build(final char[] password)
        throws OperatorCreationException
    {
        return new InputDecryptorProvider()
        {
            public InputDecryptor get(final AlgorithmIdentifier algorithm)
                throws OperatorCreationException
            {
                final Cipher cipher;

                try
                {
                    if (PEMUtilities.isPKCS5Scheme2(algorithm.getAlgorithm()))
                    {
                        PBES2Parameters params = PBES2Parameters.getInstance(algorithm.getParameters());
                        KeyDerivationFunc func = params.getKeyDerivationFunc();
                        EncryptionScheme scheme = params.getEncryptionScheme();
                        PBKDF2Params defParams = (PBKDF2Params)func.getParameters();

                        int iterationCount = defParams.getIterationCount().intValue();
                        byte[] salt = defParams.getSalt();

                        String oid = scheme.getAlgorithm().getId();

                        SecretKey key;

                        if (PEMUtilities.isHmacSHA1(defParams.getPrf()))
                        {
                            key = PEMUtilities.generateSecretKeyForPKCS5Scheme2(helper, oid, password, salt, iterationCount);
                        }
                        else
                        {
                            key = PEMUtilities.generateSecretKeyForPKCS5Scheme2(helper, oid, password, salt, iterationCount, defParams.getPrf());
                        }
                        
                        cipher = helper.createCipher(PEMUtilities.getCipherName(scheme.getAlgorithm()));
                        AlgorithmParameters algParams = helper.createAlgorithmParameters(oid);

                        algParams.init(scheme.getParameters().toASN1Primitive().getEncoded());

                        cipher.init(Cipher.DECRYPT_MODE, key, algParams);
                    }
                    else if (PEMUtilities.isPKCS12(algorithm.getAlgorithm()))
                    {
                        PKCS12PBEParams params = PKCS12PBEParams.getInstance(algorithm.getParameters());

                        cipher = helper.createCipher(PEMUtilities.getCipherName(algorithm.getAlgorithm()));

                        cipher.init(Cipher.DECRYPT_MODE, new PKCS12KeyWithParameters(password, params.getIV(), params.getIterations().intValue()));
                    }
                    else if (PEMUtilities.isPKCS5Scheme1(algorithm.getAlgorithm()))
                    {
                        PBEParameter params = PBEParameter.getInstance(algorithm.getParameters());

                        cipher = helper.createCipher(PEMUtilities.getCipherName(algorithm.getAlgorithm()));

                        cipher.init(Cipher.DECRYPT_MODE, new PBKDF1KeyWithParameters(password, new CharToByteConverter()
                        {
                            public String getType()
                            {
                                return "ASCII";
                            }

                            public byte[] convert(char[] password)
                            {
                                return Strings.toByteArray(password);     // just drop hi-order byte.
                            }
                        }, params.getSalt(), params.getIterationCount().intValue()));
                    }
                    else
                    {
                        throw new PEMException("Unknown algorithm: " + algorithm.getAlgorithm());
                    }

                    return new InputDecryptor()
                    {
                        public AlgorithmIdentifier getAlgorithmIdentifier()
                        {
                            return algorithm;
                        }

                        public InputStream getInputStream(InputStream encIn)
                        {
                            return new CipherInputStream(encIn, cipher);
                        }
                    };
                }
                catch (IOException e)
                {
                    throw new OperatorCreationException(algorithm.getAlgorithm() + " not available: " + e.getMessage(), e);
                }
                catch (GeneralSecurityException e)
                {
                    throw new OperatorCreationException(algorithm.getAlgorithm() + " not available: " + e.getMessage(), e);
                }
            };
        };
    }
}
