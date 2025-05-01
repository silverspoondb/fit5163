from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography import x509
from cryptography.x509.oid import NameOID
from datetime import datetime, timedelta, timezone
import os
import uuid

class CertificateAuthority:
    def __init__(self, name, parent=None):
        self.name = name
        self.parent = parent
        self._private_key = None
        self._public_key = None
        self.certificate = None
        self.issued_certs = {}
        self.revoked_certs = set()
        self._initialize_ca()



    def _initialize_ca(self):
        """Initialize CA with key pair and certificate"""
        self._generate_and_validate_keys()
        if self.parent is None:
            self.certificate = self._generate_self_signed_cert()
        else:
            self.certificate = self.parent.issue_certificate(
                self.name, self.public_key, is_ca=True)
        print(f"\n[CA Initialized] {self.name} ready")
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
        # Validate the consistency of CA key
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
        # verify the validity of the signature
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

    # debug and validate
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
        print(f"validity period: {cert.not_valid_before_utc} 至 {cert.not_valid_after_utc}")
        print(f"algorithm: {cert.signature_algorithm_oid._name}")
        print(f"public key fingerprint: {cert.public_key().public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).hex()[:16]}...")

    def process_csr_request(self, encrypted_package):
        """process encrypted CSR request"""
        try:
            # decrypt AES key
            aes_key = self.private_key.decrypt(
                encrypted_package['encrypted_aes_key'],
                padding.OAEP(
                    mgf=padding.MGF1(hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )

            # decrypt CSR data
            cipher = Cipher(
                algorithms.AES(aes_key),
                modes.GCM(encrypted_package['iv'], encrypted_package['tag']),
                backend=default_backend()
            )
            decryptor = cipher.decryptor()
            csr_der = decryptor.update(encrypted_package['encrypted_csr']) + decryptor.finalize()

            # load and validate CSR
            csr = x509.load_der_x509_csr(csr_der, default_backend())
            if not self._validate_csr(csr):
                raise ValueError("CSR validation failed")

            print(f"[CSR Processed] Request from {csr.subject.rfc4514_string()} verified")
            return csr.public_key(), csr.subject
        except Exception as e:
            print(f"[CSR Error] {str(e)}")
            return None, None

    def _validate_csr(self, csr):
        """validate CSR contents"""
        # verify signature
        try:
            csr.public_key().verify(
                csr.signature,
                csr.tbs_certrequest_bytes,
                padding.PKCS1v15(),
                hashes.SHA256()
            )
        except:
            raise ValueError("Invalid CSR signature")

        # validate subject format
        subject = csr.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        if not subject or len(subject) != 1:
            raise ValueError("Invalid subject name")

        return True

class Client:
    def __init__(self, name):
        self.client_id = str(uuid.uuid4())  # 生成唯一客户端ID
        self.name = name
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        self.public_key = self.private_key.public_key()
        self.certificate = None
        self._validate_key_pair()
        self.print_client_info()

    def print_client_info(self):
        """Display client credentials"""
        print(f"\n[Client Registered]")
        print(f"Name: {self.name}")
        print(f"ID  : {self.client_id}")
        print("Public Key:")
        print(self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode('utf-8'))

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
        """Create encrypted certificate request"""
        # Build CSR with client ID
        csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, self.name),
            x509.NameAttribute(NameOID.USER_ID, self.client_id)
        ])).sign(self.private_key, hashes.SHA256(), default_backend())

        # Hybrid encryption
        aes_key = os.urandom(32)
        iv = os.urandom(12)
        cipher = Cipher(algorithms.AES(aes_key), modes.GCM(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        encrypted_csr = encryptor.update(csr.public_bytes(serialization.Encoding.DER)) + encryptor.finalize()

        # Encrypt AES key
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

def interactive_client_registration():
    """Handle client registration through CLI"""
    clients = []
    for i in range(3):
        while True:
            name = input(f"\nEnter client {i+1} name (q to quit): ").strip()
            if name.lower() == 'q':
                return None
            if not name:
                print("Name cannot be empty")
                continue
            clients.append(Client(name))
            break
    return clients

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
    # Initialize PKI hierarchy
    root_ca = CertificateAuthority("Root CA")
    sub_ca1 = CertificateAuthority("Sub CA 1", parent=root_ca)
    sub_ca2 = CertificateAuthority("Sub CA 2", parent=root_ca)

    # Register clients
    clients = interactive_client_registration()
    if not clients:
        exit

    # Process each client
    for idx, client in enumerate(clients):
        # Assign to different sub CAs
        target_ca = sub_ca1 if idx < 2 else sub_ca2

        print(f"\nProcessing {client.name} with {target_ca.name}")
        encrypted_package = client.generate_encrypted_csr(target_ca.public_key)

        # Sub CA processes request
        pub_key, subject = target_ca.process_csr_request(encrypted_package)

        if pub_key and subject:
            # Verify client ID
            if subject.get_attributes_for_oid(NameOID.USER_ID)[0].value == client.client_id:
                print("Client ID verified")

                # Issue certificate
                client.certificate = target_ca.issue_certificate(
                    client.name,
                    pub_key
                )
                print(f"Certificate issued for {client.name}")
            else:
                print("Warning: Client ID mismatch")
        else:
            print("Certificate issuance failed")

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