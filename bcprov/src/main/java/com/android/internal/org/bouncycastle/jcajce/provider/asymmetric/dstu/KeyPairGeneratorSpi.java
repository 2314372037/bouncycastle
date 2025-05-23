package com.android.internal.org.bouncycastle.jcajce.provider.asymmetric.dstu;

import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidParameterException;
import java.security.KeyPair;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.ECGenParameterSpec;

import com.android.internal.org.bouncycastle.asn1.ASN1ObjectIdentifier;
import com.android.internal.org.bouncycastle.asn1.ua.DSTU4145NamedCurves;
import com.android.internal.org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import com.android.internal.org.bouncycastle.crypto.generators.DSTU4145KeyPairGenerator;
import com.android.internal.org.bouncycastle.crypto.generators.ECKeyPairGenerator;
import com.android.internal.org.bouncycastle.crypto.params.DSTU4145Parameters;
import com.android.internal.org.bouncycastle.crypto.params.ECDomainParameters;
import com.android.internal.org.bouncycastle.crypto.params.ECKeyGenerationParameters;
import com.android.internal.org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import com.android.internal.org.bouncycastle.crypto.params.ECPublicKeyParameters;
import com.android.internal.org.bouncycastle.jcajce.provider.asymmetric.util.EC5Util;
import com.android.internal.org.bouncycastle.jcajce.spec.DSTU4145ParameterSpec;
import com.android.internal.org.bouncycastle.jce.provider.BouncyCastleProvider;
import com.android.internal.org.bouncycastle.jce.spec.ECNamedCurveGenParameterSpec;
import com.android.internal.org.bouncycastle.jce.spec.ECNamedCurveSpec;
import com.android.internal.org.bouncycastle.jce.spec.ECParameterSpec;
import com.android.internal.org.bouncycastle.math.ec.ECCurve;
import com.android.internal.org.bouncycastle.math.ec.ECPoint;

public class KeyPairGeneratorSpi
    extends java.security.KeyPairGenerator
{
    Object ecParams = null;
    ECKeyPairGenerator engine = new DSTU4145KeyPairGenerator();

    String algorithm = "DSTU4145";
    ECKeyGenerationParameters param;
    //int strength = 239;
    SecureRandom random = null;
    boolean initialised = false;

    public KeyPairGeneratorSpi()
    {
        super("DSTU4145");
    }

    public void initialize(
        int strength,
        SecureRandom random)
    {
        this.random = random;

        if (ecParams != null)
        {
            try
            {
                initialize((ECGenParameterSpec)ecParams, random);
            }
            catch (InvalidAlgorithmParameterException e)
            {
                throw new InvalidParameterException("key size not configurable.");
            }
        }
        else
        {
            throw new InvalidParameterException("unknown key size.");
        }
    }

    public void initialize(
        AlgorithmParameterSpec params,
        SecureRandom random)
        throws InvalidAlgorithmParameterException
    {
        if (params instanceof ECParameterSpec)
        {
            ECParameterSpec p = (ECParameterSpec)params;
            this.ecParams = params;

            param = new ECKeyGenerationParameters(new ECDomainParameters(p.getCurve(), p.getG(), p.getN(), p.getH()), random);

            engine.init(param);
            initialised = true;
        }
        else if (params instanceof java.security.spec.ECParameterSpec)
        {
            java.security.spec.ECParameterSpec p = (java.security.spec.ECParameterSpec)params;
            this.ecParams = params;

            ECCurve curve = EC5Util.convertCurve(p.getCurve());
            ECPoint g = EC5Util.convertPoint(curve, p.getGenerator());

            if (p instanceof DSTU4145ParameterSpec)
            {
                DSTU4145ParameterSpec dstuSpec = (DSTU4145ParameterSpec)p;

                param = new ECKeyGenerationParameters(new DSTU4145Parameters(
                    new ECDomainParameters(curve, g, p.getOrder(), BigInteger.valueOf(p.getCofactor())), dstuSpec.getDKE()), random);
            }
            else
            {
                param = new ECKeyGenerationParameters(new ECDomainParameters(curve, g, p.getOrder(), BigInteger.valueOf(p.getCofactor())), random);
            }
            engine.init(param);
            initialised = true;
        }
        else if (params instanceof ECGenParameterSpec || params instanceof ECNamedCurveGenParameterSpec)
        {
            String curveName;

            if (params instanceof ECGenParameterSpec)
            {
                curveName = ((ECGenParameterSpec)params).getName();
            }
            else
            {
                curveName = ((ECNamedCurveGenParameterSpec)params).getName();
            }

            //ECDomainParameters ecP = ECGOST3410NamedCurves.getByName(curveName);
            ECDomainParameters ecP = DSTU4145NamedCurves.getByOID(new ASN1ObjectIdentifier(curveName));
            if (ecP == null)
            {
                throw new InvalidAlgorithmParameterException("unknown curve name: " + curveName);
            }

            this.ecParams = new ECNamedCurveSpec(
                curveName,
                ecP.getCurve(),
                ecP.getG(),
                ecP.getN(),
                ecP.getH(),
                ecP.getSeed());

            java.security.spec.ECParameterSpec p = (java.security.spec.ECParameterSpec)ecParams;

            ECCurve curve = EC5Util.convertCurve(p.getCurve());
            ECPoint g = EC5Util.convertPoint(curve, p.getGenerator());

            param = new ECKeyGenerationParameters(new ECDomainParameters(curve, g, p.getOrder(), BigInteger.valueOf(p.getCofactor())), random);

            engine.init(param);
            initialised = true;
        }
        else if (params == null && BouncyCastleProvider.CONFIGURATION.getEcImplicitlyCa() != null)
        {
            ECParameterSpec p = BouncyCastleProvider.CONFIGURATION.getEcImplicitlyCa();
            this.ecParams = params;

            param = new ECKeyGenerationParameters(new ECDomainParameters(p.getCurve(), p.getG(), p.getN(), p.getH()), random);

            engine.init(param);
            initialised = true;
        }
        else if (params == null && BouncyCastleProvider.CONFIGURATION.getEcImplicitlyCa() == null)
        {
            throw new InvalidAlgorithmParameterException("null parameter passed but no implicitCA set");
        }
        else
        {
            throw new InvalidAlgorithmParameterException("parameter object not a ECParameterSpec: " + params.getClass().getName());
        }
    }

    public KeyPair generateKeyPair()
    {
        if (!initialised)
        {
            throw new IllegalStateException("DSTU Key Pair Generator not initialised");
        }

        AsymmetricCipherKeyPair pair = engine.generateKeyPair();
        ECPublicKeyParameters pub = (ECPublicKeyParameters)pair.getPublic();
        ECPrivateKeyParameters priv = (ECPrivateKeyParameters)pair.getPrivate();

        if (ecParams instanceof ECParameterSpec)
        {
            ECParameterSpec p = (ECParameterSpec)ecParams;

            BCDSTU4145PublicKey pubKey = new BCDSTU4145PublicKey(algorithm, pub, p);
            return new KeyPair(pubKey,
                new BCDSTU4145PrivateKey(algorithm, priv, pubKey, p));
        }
        else if (ecParams == null)
        {
            return new KeyPair(new BCDSTU4145PublicKey(algorithm, pub),
                new BCDSTU4145PrivateKey(algorithm, priv));
        }
        else
        {
            java.security.spec.ECParameterSpec p = (java.security.spec.ECParameterSpec)ecParams;

            BCDSTU4145PublicKey pubKey = new BCDSTU4145PublicKey(algorithm, pub, p);

            return new KeyPair(pubKey, new BCDSTU4145PrivateKey(algorithm, priv, pubKey, p));
        }
    }
}

