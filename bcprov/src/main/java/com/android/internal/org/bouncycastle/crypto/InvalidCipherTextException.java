package com.android.internal.org.bouncycastle.crypto;

/**
 * this exception is thrown whenever we find something we don't expect in a
 * message.
 */
public class InvalidCipherTextException 
    extends CryptoException
{
    /**
     * base constructor.
     */
    public InvalidCipherTextException()
    {
    }

    /**
     * create a InvalidCipherTextException with the given message.
     *
     * @param message the message to be carried with the exception.
     */
    public InvalidCipherTextException(
        String  message)
    {
        super(message);
    }

    /**
     * create a InvalidCipherTextException with the given message.
     *
     * @param message the message to be carried with the exception.
     * @param cause the root cause of the exception.
     */
    public InvalidCipherTextException(
        String  message,
        Throwable cause)
    {
        super(message, cause);
    }
}
