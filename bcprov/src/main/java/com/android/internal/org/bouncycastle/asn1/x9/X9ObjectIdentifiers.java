package com.android.internal.org.bouncycastle.asn1.x9;

import com.android.internal.org.bouncycastle.asn1.ASN1ObjectIdentifier;

/**
 *
 * Object identifiers for the various X9 standards.
 * <pre>
 * ansi-X9-62 OBJECT IDENTIFIER ::= { iso(1) member-body(2)
 *                                    us(840) ansi-x962(10045) }
 * </pre>
 */
public interface X9ObjectIdentifiers
{
    /** Base OID: 1.2.840.10045 */
    ASN1ObjectIdentifier ansi_X9_62 = new ASN1ObjectIdentifier("1.2.840.10045");

    /** OID: 1.2.840.10045.1 */
    ASN1ObjectIdentifier id_fieldType = ansi_X9_62.branch("1");

    /** OID: 1.2.840.10045.1.1 */
    ASN1ObjectIdentifier prime_field = id_fieldType.branch("1");

    /** OID: 1.2.840.10045.1.2 */
    ASN1ObjectIdentifier characteristic_two_field = id_fieldType.branch("2");

    /** OID: 1.2.840.10045.1.2.3.1 */
    ASN1ObjectIdentifier gnBasis = characteristic_two_field.branch("3.1");

    /** OID: 1.2.840.10045.1.2.3.2 */
    ASN1ObjectIdentifier tpBasis = characteristic_two_field.branch("3.2");

    /** OID: 1.2.840.10045.1.2.3.3 */
    ASN1ObjectIdentifier ppBasis = characteristic_two_field.branch("3.3");

    /** OID: 1.2.840.10045.4 */
    ASN1ObjectIdentifier id_ecSigType = ansi_X9_62.branch("4");

    /** OID: 1.2.840.10045.4.1 */
    ASN1ObjectIdentifier ecdsa_with_SHA1 = id_ecSigType.branch("1");

    /** OID: 1.2.840.10045.2 */
    ASN1ObjectIdentifier id_publicKeyType = ansi_X9_62.branch("2");

    /** OID: 1.2.840.10045.2.1 */
    ASN1ObjectIdentifier id_ecPublicKey = id_publicKeyType.branch("1");

    /** OID: 1.2.840.10045.4.3 */
    ASN1ObjectIdentifier ecdsa_with_SHA2 = id_ecSigType.branch("3");

    /** OID: 1.2.840.10045.4.3.1 */
    ASN1ObjectIdentifier ecdsa_with_SHA224 = ecdsa_with_SHA2.branch("1");

    /** OID: 1.2.840.10045.4.3.2 */
    ASN1ObjectIdentifier ecdsa_with_SHA256 = ecdsa_with_SHA2.branch("2");

    /** OID: 1.2.840.10045.4.3.3 */
    ASN1ObjectIdentifier ecdsa_with_SHA384 = ecdsa_with_SHA2.branch("3");

    /** OID: 1.2.840.10045.4.3.4 */
    ASN1ObjectIdentifier ecdsa_with_SHA512 = ecdsa_with_SHA2.branch("4");

    /**
     * Named curves base
     * <p>
     * OID: 1.2.840.10045.3
     */
    ASN1ObjectIdentifier ellipticCurve = ansi_X9_62.branch("3");

    /**
     * Two Curves
     * <p>
     * OID: 1.2.840.10045.3.0
     */
    ASN1ObjectIdentifier  cTwoCurve = ellipticCurve.branch("0");

    /** Two Curve c2pnb163v1, OID: 1.2.840.10045.3.0.1 */
    ASN1ObjectIdentifier c2pnb163v1 = cTwoCurve.branch("1");
    /** Two Curve c2pnb163v2, OID: 1.2.840.10045.3.0.2 */
    ASN1ObjectIdentifier c2pnb163v2 = cTwoCurve.branch("2");
    /** Two Curve c2pnb163v3, OID: 1.2.840.10045.3.0.3 */
    ASN1ObjectIdentifier c2pnb163v3 = cTwoCurve.branch("3");
    /** Two Curve c2pnb176w1, OID: 1.2.840.10045.3.0.4 */
    ASN1ObjectIdentifier c2pnb176w1 = cTwoCurve.branch("4");
    /** Two Curve c2tnb191v1, OID: 1.2.840.10045.3.0.5 */
    ASN1ObjectIdentifier c2tnb191v1 = cTwoCurve.branch("5");
    /** Two Curve c2tnb191v2, OID: 1.2.840.10045.3.0.6 */
    ASN1ObjectIdentifier c2tnb191v2 = cTwoCurve.branch("6");
    /** Two Curve c2tnb191v3, OID: 1.2.840.10045.3.0.7 */
    ASN1ObjectIdentifier c2tnb191v3 = cTwoCurve.branch("7");
    /** Two Curve c2onb191v4, OID: 1.2.840.10045.3.0.8 */
    ASN1ObjectIdentifier c2onb191v4 = cTwoCurve.branch("8");
    /** Two Curve c2onb191v5, OID: 1.2.840.10045.3.0.9 */
    ASN1ObjectIdentifier c2onb191v5 = cTwoCurve.branch("9");
    /** Two Curve c2pnb208w1, OID: 1.2.840.10045.3.0.10 */
    ASN1ObjectIdentifier c2pnb208w1 = cTwoCurve.branch("10");
    /** Two Curve c2tnb239v1, OID: 1.2.840.10045.3.0.11 */
    ASN1ObjectIdentifier c2tnb239v1 = cTwoCurve.branch("11");
    /** Two Curve c2tnb239v2, OID: 1.2.840.10045.3.0.12 */
    ASN1ObjectIdentifier c2tnb239v2 = cTwoCurve.branch("12");
    /** Two Curve c2tnb239v3, OID: 1.2.840.10045.3.0.13 */
    ASN1ObjectIdentifier c2tnb239v3 = cTwoCurve.branch("13");
    /** Two Curve c2onb239v4, OID: 1.2.840.10045.3.0.14 */
    ASN1ObjectIdentifier c2onb239v4 = cTwoCurve.branch("14");
    /** Two Curve c2onb239v5, OID: 1.2.840.10045.3.0.15 */
    ASN1ObjectIdentifier c2onb239v5 = cTwoCurve.branch("15");
    /** Two Curve c2pnb272w1, OID: 1.2.840.10045.3.0.16 */
    ASN1ObjectIdentifier c2pnb272w1 = cTwoCurve.branch("16");
    /** Two Curve c2pnb304w1, OID: 1.2.840.10045.3.0.17 */
    ASN1ObjectIdentifier c2pnb304w1 = cTwoCurve.branch("17");
    /** Two Curve c2tnb359v1, OID: 1.2.840.10045.3.0.18 */
    ASN1ObjectIdentifier c2tnb359v1 = cTwoCurve.branch("18");
    /** Two Curve c2pnb368w1, OID: 1.2.840.10045.3.0.19 */
    ASN1ObjectIdentifier c2pnb368w1 = cTwoCurve.branch("19");
    /** Two Curve c2tnb431r1, OID: 1.2.840.10045.3.0.20 */
    ASN1ObjectIdentifier c2tnb431r1 = cTwoCurve.branch("20");

    /**
     * Prime Curves
     * <p>
     * OID: 1.2.840.10045.3.1
     */
    ASN1ObjectIdentifier primeCurve = ellipticCurve.branch("1");

    /** Prime Curve prime192v1, OID: 1.2.840.10045.3.1.1 */
    ASN1ObjectIdentifier prime192v1 = primeCurve.branch("1");
    /** Prime Curve prime192v2, OID: 1.2.840.10045.3.1.2 */
    ASN1ObjectIdentifier prime192v2 = primeCurve.branch("2");
    /** Prime Curve prime192v3, OID: 1.2.840.10045.3.1.3 */
    ASN1ObjectIdentifier prime192v3 = primeCurve.branch("3");
    /** Prime Curve prime239v1, OID: 1.2.840.10045.3.1.4 */
    ASN1ObjectIdentifier prime239v1 = primeCurve.branch("4");
    /** Prime Curve prime239v2, OID: 1.2.840.10045.3.1.5 */
    ASN1ObjectIdentifier prime239v2 = primeCurve.branch("5");
    /** Prime Curve prime239v3, OID: 1.2.840.10045.3.1.6 */
    ASN1ObjectIdentifier prime239v3 = primeCurve.branch("6");
    /** Prime Curve prime256v1, OID: 1.2.840.10045.3.1.7 */
    ASN1ObjectIdentifier prime256v1 = primeCurve.branch("7");

    /**
     * DSA
     * <pre>
     * dsapublicnumber OBJECT IDENTIFIER ::= { iso(1) member-body(2)
     *                                         us(840) ansi-x957(10040) number-type(4) 1 }
     * </pre>
     * Base OID: 1.2.840.10040.4.1
     */
    ASN1ObjectIdentifier id_dsa = new ASN1ObjectIdentifier("1.2.840.10040.4.1");

    /**
     * <pre>
     * id-dsa-with-sha1 OBJECT IDENTIFIER ::= {
     *     iso(1) member-body(2) us(840) x9-57(10040) x9cm(4) 3 }
     * </pre>
     * OID: 1.2.840.10040.4.3
     */
    ASN1ObjectIdentifier id_dsa_with_sha1 = new ASN1ObjectIdentifier("1.2.840.10040.4.3");

    /**
     * X9.63 - Signature Specification
     * <p>
     * Base OID: 1.3.133.16.840.63.0
     */
    ASN1ObjectIdentifier x9_63_scheme = new ASN1ObjectIdentifier("1.3.133.16.840.63.0");
    /** OID: 1.3.133.16.840.63.0.2 */
    ASN1ObjectIdentifier dhSinglePass_stdDH_sha1kdf_scheme      = x9_63_scheme.branch("2");
    /** OID: 1.3.133.16.840.63.0.3 */
    ASN1ObjectIdentifier dhSinglePass_cofactorDH_sha1kdf_scheme = x9_63_scheme.branch("3");
    /** OID: 1.3.133.16.840.63.0.16 */
    ASN1ObjectIdentifier mqvSinglePass_sha1kdf_scheme           = x9_63_scheme.branch("16");

    /**
     * X9.42
     */

    ASN1ObjectIdentifier ansi_X9_42 = new ASN1ObjectIdentifier("1.2.840.10046");

    /**
     * Diffie-Hellman
     * <pre>
     * dhpublicnumber OBJECT IDENTIFIER ::= {
     *    iso(1) member-body(2)  us(840) ansi-x942(10046) number-type(2) 1
     * }
     * </pre>
     * OID: 1.2.840.10046.2.1
     */
    ASN1ObjectIdentifier dhpublicnumber = ansi_X9_42.branch("2.1");

    /** X9.42 schemas base OID: 1.2.840.10046.3 */
    ASN1ObjectIdentifier x9_42_schemes = ansi_X9_42.branch("3");
    /** X9.42 dhStatic OID: 1.2.840.10046.3.1 */
    ASN1ObjectIdentifier dhStatic        = x9_42_schemes.branch("1");
    /** X9.42 dhEphem OID: 1.2.840.10046.3.2 */
    ASN1ObjectIdentifier dhEphem         = x9_42_schemes.branch("2");
    /** X9.42 dhOneFlow OID: 1.2.840.10046.3.3 */
    ASN1ObjectIdentifier dhOneFlow       = x9_42_schemes.branch("3");
    /** X9.42 dhHybrid1 OID: 1.2.840.10046.3.4 */
    ASN1ObjectIdentifier dhHybrid1       = x9_42_schemes.branch("4");
    /** X9.42 dhHybrid2 OID: 1.2.840.10046.3.5 */
    ASN1ObjectIdentifier dhHybrid2       = x9_42_schemes.branch("5");
    /** X9.42 dhHybridOneFlow OID: 1.2.840.10046.3.6 */
    ASN1ObjectIdentifier dhHybridOneFlow = x9_42_schemes.branch("6");
    /** X9.42 MQV2 OID: 1.2.840.10046.3.7 */
    ASN1ObjectIdentifier mqv2            = x9_42_schemes.branch("7");
    /** X9.42 MQV1 OID: 1.2.840.10046.3.8 */
    ASN1ObjectIdentifier mqv1            = x9_42_schemes.branch("8");

    /**
     * X9.44
     * <pre>
     *    x9-44 OID ::= {
     *      iso(1) identified-organization(3) tc68(133) country(16) x9(840)
     *      x9Standards(9) x9-44(44)
     *   }
     * </pre>
     */

    ASN1ObjectIdentifier x9_44 = new ASN1ObjectIdentifier("1.3.133.16.840.9.44");

    ASN1ObjectIdentifier x9_44_components = x9_44.branch("1");

    ASN1ObjectIdentifier id_kdf_kdf2 = x9_44_components.branch("1");
    ASN1ObjectIdentifier id_kdf_kdf3 = x9_44_components.branch("2");
}
