package com.android.internal.org.bouncycastle.tsp;

public class TSPException
    extends Exception
{
    Throwable underlyingException;

    public TSPException(String message)
    {
        super(message);
    }

    public TSPException(String message, Throwable e)
    {
        super(message);
        underlyingException = e;
    }

    public Exception getUnderlyingException()
    {
        return (Exception)underlyingException;
    }

    public Throwable getCause()
    {
        return underlyingException;
    }
}
