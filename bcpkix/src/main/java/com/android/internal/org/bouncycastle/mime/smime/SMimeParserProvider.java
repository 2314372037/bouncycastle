package com.android.internal.org.bouncycastle.mime.smime;

import java.io.IOException;
import java.io.InputStream;

import com.android.internal.org.bouncycastle.mime.BasicMimeParser;
import com.android.internal.org.bouncycastle.mime.Headers;
import com.android.internal.org.bouncycastle.mime.MimeParser;
import com.android.internal.org.bouncycastle.mime.MimeParserProvider;
import com.android.internal.org.bouncycastle.operator.DigestCalculatorProvider;

public class SMimeParserProvider
    implements MimeParserProvider
{
    private final String defaultContentTransferEncoding;
    private final DigestCalculatorProvider digestCalculatorProvider;

    public SMimeParserProvider(String defaultContentTransferEncoding, DigestCalculatorProvider digestCalculatorProvider)
    {
        this.defaultContentTransferEncoding = defaultContentTransferEncoding;
        this.digestCalculatorProvider = digestCalculatorProvider;
    }

    public MimeParser createParser(InputStream source)
        throws IOException
    {
        return new BasicMimeParser(new SMimeParserContext(defaultContentTransferEncoding, digestCalculatorProvider),
            SMimeUtils.autoBuffer(source));
    }

    public MimeParser createParser(Headers headers, InputStream source)
        throws IOException
    {
        return new BasicMimeParser(new SMimeParserContext(defaultContentTransferEncoding, digestCalculatorProvider),
            headers, SMimeUtils.autoBuffer(source));
    }
}
