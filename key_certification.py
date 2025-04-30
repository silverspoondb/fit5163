from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography import x509
from cryptography.x509.oid import NameOID
from datetime import datetime, timedelta, timezone
import os


class CertificateAuthority:
    def __init__(self, name, parent=None):
        self.name = name
        self.parent = parent
        self._private_key = None
        self._public_key = None
        self.certificate = None
        self.issued_certs = {}
        self.revoked_certs = set()

        # Initialize the key pair and verify.
        self._generate_and_validate_keys()

        if self.parent is None:
            self.certificate = self._generate_self_signed_cert()
        else:
            self.certificate = self.parent.issue_certificate(self.name, self.public_key, is_ca=True)

        print(f"\n=== {self.name} Initialize ===")
        self.debug_certificate(self.certificate)

    def _generate_and_validate_keys(self):
        # generate RSA key pairs
        self._private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=4096,
            backend=default_backend()
        )
        self._public_key = self._private_key.public_key()

        # debug the RSA key pairs
        test_msg = b"Key Pair Validation"
        try:
            sig = self._private_key.sign(
                test_msg,
                padding.PKCS1v15(),
                hashes.SHA256()
            )
            self._public_key.verify(
                sig,
                test_msg,
                padding.PKCS1v15(),
                hashes.SHA256()
            )
        except Exception as e:
            raise RuntimeError(f"{self.name} The key pair verification failed") from e

    @property
    def private_key(self):
        return self._private_key

    @property
    def public_key(self):
        return self._public_key

    def _generate_self_signed_cert(self):
        """Generate a self-signed root certificate"""
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, self.name)
        ])
        return (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(self.public_key)
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.now(timezone.utc) - timedelta(minutes=5))
            .not_valid_after(datetime.now(timezone.utc) + timedelta(days=365))
            .add_extension(
                x509.BasicConstraints(ca=True, path_length=2),
                critical=True,
            )
            .sign(self.private_key, hashes.SHA256(), default_backend())
        )

    def issue_certificate(self, subject_name, subject_pub_key, is_ca=False):
        # Verify the validity of own key
        self._validate_key_consistency()

        builder = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([
                x509.NameAttribute(NameOID.COMMON_NAME, subject_name)
            ]))
            .issuer_name(self.certificate.subject)
            .public_key(subject_pub_key)
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.now(timezone.utc) - timedelta(minutes=5))
            .not_valid_after(datetime.now(timezone.utc) + timedelta(days=180))
        )

        if is_ca:
            builder = builder.add_extension(
                x509.BasicConstraints(ca=True, path_length=1),
                critical=True,
            )
        else:
            builder = builder.add_extension(
                x509.BasicConstraints(ca=False, path_length=None),
                critical=True,
            )

        cert = builder.sign(self.private_key, hashes.SHA256(), default_backend())
        # Verify the validity of the signature
        self._verify_cert_signature(cert)
        self.issued_certs[cert.serial_number] = cert
        return cert

    def _validate_key_consistency(self):
        test_msg = b"CA Key Consistency Check"
        try:
            sig = self.private_key.sign(
                test_msg,
                padding.PKCS1v15(),
                hashes.SHA256()
            )
            self.public_key.verify(
                sig,
                test_msg,
                padding.PKCS1v15(),
                hashes.SHA256()
            )
        except Exception as e:
            raise RuntimeError(f"{self.name} The key pairs do not match") from e

    def _verify_cert_signature(self, cert):
        try:
            self.public_key.verify(
                cert.signature,
                cert.tbs_certificate_bytes,
                padding.PKCS1v15(),
                cert.signature_hash_algorithm,
            )
        except Exception as e:
            raise RuntimeError(f"The certificate signature is invalid: {str(e)}") from e

    # validate
    def validate_certificate(self, cert):

        print(f"\n=== certificate {cert.serial_number} ===")

        # 1
        if cert.serial_number in self.revoked_certs:
            print("x certificate has been revoked ")
            return False
        print("v certificate has not been revoked")

        # 2
        now = datetime.now(timezone.utc)
        if not (cert.not_valid_before_utc <= now <= cert.not_valid_after_utc):
            print(f"x The validity period of the certificate is invalid ({cert.not_valid_before_utc} 至 {cert.not_valid_after_utc})")
            return False
        print("v The certificate is within its validity period")

        # 3.
        try:
            self.public_key.verify(
                cert.signature,
                cert.tbs_certificate_bytes,
                padding.PKCS1v15(),
                cert.signature_hash_algorithm,
            )
            print("v signature verification succeed")
            return True
        except Exception as e:
            print(f"x signature verification failed: {str(e)}")
            return False

    def revoke_certificate(self, serial_number):
        if serial_number in self.issued_certs:
            self.revoked_certs.add(serial_number)
            print(f"revoked certificate {serial_number}")
        else:
            print("warning: attempt to revoke unissued certificates")

    def debug_certificate(self, cert):
        print(f"\n【certificate details】{cert.subject.rfc4514_string()}")
        print(f"issuer: {cert.issuer.rfc4514_string()}")
        print(f"serial_number: {cert.serial_number}")
        print(f"validity period: {cert.not_valid_before_utc} to {cert.not_valid_after_utc}")
        print(f"algorithm: {cert.signature_algorithm_oid._name}")
        print(f"public key fingerprint: {cert.public_key().public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).hex()[:16]}...")


class Client:
    def __init__(self, name):
        self.name = name
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        self.public_key = self.private_key.public_key()
        self.certificate = None

        self._validate_key_pair()

    def _validate_key_pair(self):
        test_msg = b"Client Key Validation"
        try:
            sig = self.private_key.sign(
                test_msg,
                padding.PKCS1v15(),
                hashes.SHA256()
            )
            self.public_key.verify(
                sig,
                test_msg,
                padding.PKCS1v15(),
                hashes.SHA256()
            )
        except Exception as e:
            raise RuntimeError("the client key pair is invalid") from e

    def generate_encrypted_csr(self, ca_public_key):
        csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, self.name),
        ])).sign(self.private_key, hashes.SHA256(), default_backend())

        aes_key = os.urandom(32)
        iv = os.urandom(12)
        cipher = Cipher(algorithms.AES(aes_key), modes.GCM(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        encrypted_csr = encryptor.update(csr.public_bytes(serialization.Encoding.DER)) + encryptor.finalize()

        encrypted_aes_key = ca_public_key.encrypt(
            aes_key,
            padding.OAEP(
                mgf=padding.MGF1(hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        return {
            'iv': iv,
            'tag': encryptor.tag,
            'encrypted_aes_key': encrypted_aes_key,
            'encrypted_csr': encrypted_csr
        }


def verify_cert_chain(cert, issuer_ca):
    print("\n=== certificate chain verification ===")
    current_cert = cert
    current_ca = issuer_ca

    while current_ca is not None:
        try:
            current_ca.public_key.verify(
                current_cert.signature,
                current_cert.tbs_certificate_bytes,
                padding.PKCS1v15(),
                current_cert.signature_hash_algorithm,
            )
            print(f"v {current_ca.name} verification succeed -> {current_cert.subject.rfc4514_string()}")
        except Exception as e:
            print(f"x {current_ca.name} verification failed: {str(e)}")
            return False

        current_cert = current_ca.certificate
        current_ca = current_ca.parent

    print("v pass")
    return True


if __name__ == "__main__":
    # CA
    root_ca = CertificateAuthority("Root CA")
    sub_ca1 = CertificateAuthority("Sub CA 1", parent=root_ca)
    sub_ca2 = CertificateAuthority("Sub CA 2", parent=root_ca)

    clients = [Client("Client1"), Client("Client2"), Client("Client3")]

    for i, client in enumerate(clients):
        target_ca = sub_ca1 if i < 2 else sub_ca2

        try:
            csr_package = client.generate_encrypted_csr(target_ca.public_key)

            aes_key = target_ca.private_key.decrypt(
                csr_package['encrypted_aes_key'],
                padding.OAEP(
                    mgf=padding.MGF1(hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )

            cipher = Cipher(
                algorithms.AES(aes_key),
                modes.GCM(csr_package['iv'], csr_package['tag']),
                backend=default_backend()
            )
            decryptor = cipher.decryptor()
            csr_der = decryptor.update(csr_package['encrypted_csr']) + decryptor.finalize()
            csr = x509.load_der_x509_csr(csr_der, default_backend())
            client.certificate = target_ca.issue_certificate(client.name, csr.public_key())
            print(f"\n=== {client.name}  certificate issuance succeed ===")

        except Exception as e:
            print(f"{client.name} certificate issuance failed: {str(e)}")
            continue


    # example
    if clients[0].certificate:
        print("\n=== test ===")

        print("verification result:", sub_ca1.validate_certificate(clients[0].certificate))
        verify_cert_chain(clients[0].certificate, sub_ca1)

        print("verification result:", sub_ca2.validate_certificate(clients[0].certificate))
        verify_cert_chain(clients[0].certificate, sub_ca2)

        print("verification result:", sub_ca2.validate_certificate(clients[2].certificate))
        verify_cert_chain(clients[2].certificate, sub_ca2)

        print("\n=== revocation test ===")
        sub_ca1.revoke_certificate(clients[0].certificate.serial_number)
        print("verification result after revocation:", sub_ca1.validate_certificate(clients[0].certificate))