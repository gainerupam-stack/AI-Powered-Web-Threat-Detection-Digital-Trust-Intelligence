
"""
TrustGuard AI - TLS Certificate Analyzer

Inspects HTTPS certificates and TLS connection security.
Does not download or execute website content.
"""
from url_tls.safe_connection import open_pinned_connection
import socket
import ssl
import ipaddress
from datetime import datetime, timezone

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa, ec, dsa


def add_finding(findings, indicator, severity, evidence):
    findings.append({
        "indicator": indicator,
        "severity": severity,
        "evidence": evidence,
        "source": "tls_analyzer"
    })


def analyze_tls(hostname, port=443, timeout=5):
    findings = []
    limitations = []

    result = {
        "status": "completed",
        "hostname": hostname,
        "port": port,
        "tls_version": None,
        "cipher": None,
        "certificate": {},
        "findings": findings,
        "limitations": limitations
    }

    if not isinstance(hostname, str) or not hostname.strip():
        result["status"] = "failed"
        limitations.append("A valid hostname is required.")
        return result

    hostname = hostname.strip().rstrip(".")

    try:
        # Reject direct connections to non-public IP addresses.
        try:
            address = ipaddress.ip_address(hostname)
            if not address.is_global:
                result["status"] = "failed"
                add_finding(
                    findings,
                    "unsafe_tls_destination",
                    "high",
                    f"Non-global IP address rejected: {hostname}"
                )
                return result
        except ValueError:
            pass

        
        # Connect through the DNS-validated, IP-pinned helper.
        with open_pinned_connection(
            hostname,
            port=port,
            timeout=timeout,
            use_tls=True
        ) as tls_socket:

            result["tls_version"] = tls_socket.version()

            cipher = tls_socket.cipher()

            if cipher:
                    result["cipher"] = {
                        "name": cipher[0],
                        "protocol": cipher[1],
                        "bits": cipher[2]
                    }

            cert_der = tls_socket.getpeercert(binary_form=True)
            certificate = x509.load_der_x509_certificate(cert_der)

            now = datetime.now(timezone.utc)

            not_before = certificate.not_valid_before_utc
            not_after = certificate.not_valid_after_utc

            cert_info = {
                    "subject": certificate.subject.rfc4514_string(),
                    "issuer": certificate.issuer.rfc4514_string(),
                    "serial_number": str(certificate.serial_number),
                    "valid_from": not_before.isoformat(),
                    "valid_until": not_after.isoformat(),
                    "days_until_expiry": (not_after - now).days,
                    "signature_algorithm": certificate.signature_hash_algorithm.name
                        if certificate.signature_hash_algorithm else "unknown",
                    "hostname_verified": True,
                    "chain_verified": True
                }

                # Inspect the public key.
            public_key = certificate.public_key()

            if isinstance(public_key, rsa.RSAPublicKey):
                    key_type = "RSA"
                    key_size = public_key.key_size

                    if key_size < 2048:
                        add_finding(
                            findings,
                            "weak_rsa_key",
                            "high",
                            f"RSA key size is only {key_size} bits."
                        )

            elif isinstance(public_key, ec.EllipticCurvePublicKey):
                    key_type = "EC"
                    key_size = public_key.key_size

                    if key_size < 224:
                        add_finding(
                            findings,
                            "weak_ec_key",
                            "high",
                            f"EC key size is only {key_size} bits."
                        )

            elif isinstance(public_key, dsa.DSAPublicKey):
                    key_type = "DSA"
                    key_size = public_key.key_size

                    if key_size < 2048:
                        add_finding(
                            findings,
                            "weak_dsa_key",
                            "high",
                            f"DSA key size is only {key_size} bits."
                        )

            else:
                    key_type = type(public_key).__name__
                    key_size = getattr(public_key, "key_size", None)

            cert_info["public_key"] = {
                    "type": key_type,
                    "bits": key_size
                }

                # Detect weak certificate signature hashes.
            algorithm = cert_info["signature_algorithm"].lower()

            if algorithm in ("md5", "sha1"):
                    add_finding(
                        findings,
                        "weak_certificate_signature",
                        "high",
                        f"Certificate uses weak signature hash: {algorithm}."
                    )

                # Expiry checks.
            if now > not_after:
                    add_finding(
                        findings,
                        "expired_certificate",
                        "high",
                        "TLS certificate has expired."
                    )

            elif (not_after - now).days <= 30:
                    add_finding(
                        findings,
                        "certificate_expiring_soon",
                        "medium",
                        f"Certificate expires in {(not_after - now).days} days."
                    )

            if now < not_before:
                    add_finding(
                        findings,
                        "certificate_not_yet_valid",
                        "high",
                        "Certificate validity period has not started."
                    )

            result["certificate"] = cert_info

    except ssl.SSLCertVerificationError as error:
        result["status"] = "failed"
        add_finding(
            findings,
            "tls_certificate_verification_failed",
            "high",
            str(error)
        )

    except (socket.timeout, TimeoutError):
        result["status"] = "failed"
        limitations.append("TLS connection timed out.")

    except (socket.gaierror, OSError, ssl.SSLError, ValueError) as error:
        result["status"] = "failed"
        limitations.append(
            f"TLS analysis unavailable: {type(error).__name__}: {error}"
        )

    except Exception as error:
        result["status"] = "failed"
        limitations.append(
            f"Unexpected TLS analysis error: {type(error).__name__}"
        )

    return result
