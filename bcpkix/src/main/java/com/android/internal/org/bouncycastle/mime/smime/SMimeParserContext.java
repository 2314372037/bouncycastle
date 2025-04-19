package com.android.internal.org.bouncycastle.mime.smime;

import com.android.internal.org.bouncycastle.mime.MimeParserContext;
import com.android.internal.org.bouncycastle.operator.DigestCalculatorProvider;

public class SMimeParserContext
    implements MimeParserContext
{
    private final String defaultContentTransferEncoding;
    private final DigestCalculatorProvider digestCalculatorProvider;

    public SMimeParserContext(String defaultContentTransferEncoding, DigestCalculatorProvider digestCalculatorProvider)
    {
        this.defaultContentTransferEncoding = defaultContentTransferEncoding;
        this.digestCalculatorProvider = digestCalculatorProvider;
    }

    public String getDefaultContentTransferEncoding()
    {
        return defaultContentTransferEncoding;
    }

    public DigestCalculatorProvider getDigestCalculatorProvider()
    {
        return digestCalculatorProvider;
    }
}
