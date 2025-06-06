package com.android.internal.org.bouncycastle.jcajce.spec;

import java.security.spec.AlgorithmParameterSpec;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

public class CompositeAlgorithmSpec
    implements AlgorithmParameterSpec
{
    public static class Builder
    {
        private List<String> algorithmNames = new ArrayList<String>();
        private List<AlgorithmParameterSpec> parameterSpecs = new ArrayList<AlgorithmParameterSpec>();

        public Builder()
        {
        }

        public Builder add(String algorithmName)
        {
            return add(algorithmName, null);
        }

        public Builder add(String algorithmName, AlgorithmParameterSpec parameterSpec)
        {
            if (!algorithmNames.contains(algorithmName))
            {
                algorithmNames.add(algorithmName);
                parameterSpecs.add(parameterSpec);

                return this;
            }
            throw new IllegalStateException("cannot build with the same algorithm name added");
        }

        public CompositeAlgorithmSpec build()
        {
            if (algorithmNames.isEmpty())
            {
                throw new IllegalStateException("cannot call build with no algorithm names added");
            }

            return new CompositeAlgorithmSpec(this);
        }
    }

    private final List<String> algorithmNames;
    private final List<AlgorithmParameterSpec> parameterSpecs;

    public CompositeAlgorithmSpec(Builder builder)
    {
        this.algorithmNames = Collections.unmodifiableList(new ArrayList<String>(builder.algorithmNames));
        this.parameterSpecs = Collections.unmodifiableList(new ArrayList<AlgorithmParameterSpec>(builder.parameterSpecs));
    }

    public List<String> getAlgorithmNames()
    {
        return algorithmNames;
    }

    public List<AlgorithmParameterSpec> getParameterSpecs()
    {
        return parameterSpecs;
    }
}
