package com.android.internal.org.bouncycastle.cert.crmf;

import java.io.ByteArrayOutputStream;
import java.io.OutputStream;
import java.security.SecureRandom;

import com.android.internal.org.bouncycastle.asn1.DERNull;
import com.android.internal.org.bouncycastle.asn1.cmp.CMPObjectIdentifiers;
import com.android.internal.org.bouncycastle.asn1.cmp.PBMParameter;
import com.android.internal.org.bouncycastle.asn1.iana.IANAObjectIdentifiers;
import com.android.internal.org.bouncycastle.asn1.oiw.OIWObjectIdentifiers;
import com.android.internal.org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import com.android.internal.org.bouncycastle.operator.GenericKey;
import com.android.internal.org.bouncycastle.operator.MacCalculator;
import com.android.internal.org.bouncycastle.operator.OperatorCreationException;
import com.android.internal.org.bouncycastle.operator.PBEMacCalculatorProvider;
import com.android.internal.org.bouncycastle.operator.RuntimeOperatorException;
import com.android.internal.org.bouncycastle.util.Strings;

public class PKMACBuilder
    implements PBEMacCalculatorProvider
{
    private AlgorithmIdentifier owf;
    private int iterationCount;
    private AlgorithmIdentifier mac;
    private int saltLength = 20;
    private SecureRandom random;
    private PKMACValuesCalculator calculator;
    private PBMParameter parameters;
    private int maxIterations;

    public PKMACBuilder(PKMACValuesCalculator calculator)
    {
        this(new AlgorithmIdentifier(OIWObjectIdentifiers.idSHA1), 1000,
            new AlgorithmIdentifier(IANAObjectIdentifiers.hmacSHA1, DERNull.INSTANCE), calculator);
    }

    /**
     * Create a PKMAC builder enforcing a ceiling on the maximum iteration count.
     *
     * @param calculator     supporting calculator
     * @param maxIterations  max allowable value for iteration count.
     */
    public PKMACBuilder(PKMACValuesCalculator calculator, int maxIterations)
    {
        this.maxIterations = maxIterations;
        this.calculator = calculator;
    }

    private PKMACBuilder(AlgorithmIdentifier hashAlgorithm, int iterationCount, AlgorithmIdentifier macAlgorithm,
        PKMACValuesCalculator calculator)
    {
        this.owf = hashAlgorithm;
        this.iterationCount = iterationCount;
        this.mac = macAlgorithm;
        this.calculator = calculator;
    }

    /**
     * Set the salt length in octets.
     *
     * @param saltLength length in octets of the salt to be generated.
     * @return the generator
     */
    public PKMACBuilder setSaltLength(int saltLength)
    {
        if (saltLength < 8)
        {
            throw new IllegalArgumentException("salt length must be at least 8 bytes");
        }

        this.saltLength = saltLength;

        return this;
    }

    public PKMACBuilder setIterationCount(int iterationCount)
    {
        if (iterationCount < 100)
        {
            throw new IllegalArgumentException("iteration count must be at least 100");
        }
        checkIterationCountCeiling(iterationCount);

        this.iterationCount = iterationCount;

        return this;
    }

    public PKMACBuilder setSecureRandom(SecureRandom random)
    {
        this.random = random;

        return this;
    }

    public PKMACBuilder setParameters(PBMParameter parameters)
    {
        checkIterationCountCeiling(parameters.getIterationCount().intValueExact());

        this.parameters = parameters;

        return this;
    }

    public MacCalculator get(AlgorithmIdentifier algorithm, char[] password)
        throws OperatorCreationException
    {
        if (!CMPObjectIdentifiers.passwordBasedMac.equals(algorithm.getAlgorithm()))
        {
            throw new OperatorCreationException("protection algorithm not mac based");
        }

        this.setParameters(PBMParameter.getInstance(algorithm.getParameters()));

        try
        {
            return this.build(password);
        }
        catch (CRMFException e)
        {
            throw new OperatorCreationException(e.getMessage(), e.getCause());
        }
    }

    public MacCalculator build(char[] password)
        throws CRMFException
    {
        PBMParameter pbmParameter = parameters;        
        if (pbmParameter == null)
        {
            pbmParameter = genParameters();
        }

        return genCalculator(pbmParameter, password);
    }

    private void checkIterationCountCeiling(int iterationCount)
    {
        if (maxIterations > 0 && iterationCount > maxIterations)
        {
            throw new IllegalArgumentException("iteration count exceeds limit (" + iterationCount + " > " + maxIterations + ")");
        }
    }

    private MacCalculator genCalculator(final PBMParameter params, char[] password)
        throws CRMFException
    {
        // From RFC 4211
        //
        //   1.  Generate a random salt value S
        //
        //   2.  Append the salt to the pw.  K = pw || salt.
        //
        //   3.  Hash the value of K.  K = HASH(K)
        //
        //   4.  Iter = Iter - 1.  If Iter is greater than zero.  Goto step 3.
        //
        //   5.  Compute an HMAC as documented in [HMAC].
        //
        //       MAC = HASH( K XOR opad, HASH( K XOR ipad, data) )
        //
        //       Where opad and ipad are defined in [HMAC].
        byte[] pw = Strings.toUTF8ByteArray(password);
        byte[] salt = params.getSalt().getOctets();
        byte[] K = new byte[pw.length + salt.length];

        System.arraycopy(pw, 0, K, 0, pw.length);
        System.arraycopy(salt, 0, K, pw.length, salt.length);

        calculator.setup(params.getOwf(), params.getMac());

        int iter = params.getIterationCount().intValueExact();
        do
        {
            K = calculator.calculateDigest(K);
        }
        while (--iter > 0);

        final byte[] key = K;

        return new MacCalculator()
        {
            ByteArrayOutputStream bOut = new ByteArrayOutputStream();

            public AlgorithmIdentifier getAlgorithmIdentifier()
            {
                return new AlgorithmIdentifier(CMPObjectIdentifiers.passwordBasedMac, params);
            }

            public GenericKey getKey()
            {
                return new GenericKey(getAlgorithmIdentifier(), key);
            }

            public OutputStream getOutputStream()
            {
                return bOut;
            }

            public byte[] getMac()
            {
                try
                {
                    return calculator.calculateMac(key, bOut.toByteArray());
                }
                catch (CRMFException e)
                {
                    throw new RuntimeOperatorException("exception calculating mac: " + e.getMessage(), e);
                }
            }
        };
    }

    private PBMParameter genParameters()
    {
        byte[] salt = new byte[saltLength];

        if (random == null)
        {
            random = new SecureRandom();
        }

        random.nextBytes(salt);

        return new PBMParameter(salt, owf, iterationCount, mac);
    }
}
