package com.android.internal.org.bouncycastle.openssl;

import com.android.internal.org.bouncycastle.operator.OperatorCreationException;

public interface PEMDecryptorProvider
{
    PEMDecryptor get(String dekAlgName)
        throws OperatorCreationException;
}
