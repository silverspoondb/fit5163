from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography import x509
from cryptography.x509.oid import NameOID
from datetime import datetime, timedelta, timezone
import uuid


class CertificateAuthority:
    def __init__(self, name, parent=None):
        self.name = name
        self.parent = parent
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=4096,  # 使用4096位密钥
            backend=default_backend()
        )
        self.public_key = self.private_key.public_key()
        self.certificate = self._generate_self_signed_cert() if parent is None else None
        self.issued_certs = {}
        self.revoked_certs = set()

    def _generate_self_signed_cert(self):
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, self.name)
        ])
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(self.public_key)
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.now(timezone.utc))
            .not_valid_after(datetime.now(timezone.utc) + timedelta(days=365))
            .add_extension(
                x509.BasicConstraints(ca=True, path_length=2),
                critical=True,
            )
            .sign(self.private_key, hashes.SHA256(), default_backend())
        )
        return cert

    def issue_certificate(self, client_name, client_pub_key):
        cert = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([
                x509.NameAttribute(NameOID.COMMON_NAME, client_name)
            ]))
            .issuer_name(self.certificate.subject)
            .public_key(client_pub_key)
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.now(timezone.utc))
            .not_valid_after(datetime.now(timezone.utc) + timedelta(days=180))
            .add_extension(
                x509.BasicConstraints(ca=False, path_length=None),
                critical=True,
            )
            .sign(self.private_key, hashes.SHA256(), default_backend())
        )
        self.issued_certs[cert.serial_number] = cert
        return cert

    def revoke_certificate(self, serial_number):
        self.revoked_certs.add(serial_number)

    def validate_certificate(self, cert):
        if cert.serial_number in self.revoked_certs:
            return False

        now = datetime.now(timezone.utc)
        if not (cert.not_valid_before <= now <= cert.not_valid_after):
            return False

        try:
            verifying_key = self.parent.public_key if self.parent else self.public_key
            verifying_key.verify(
                cert.signature,
                cert.tbs_certificate_bytes,
                padding.PKCS1v15(),
                cert.signature_hash_algorithm,
            )
            return True
        except:
            return False


class Client:
    def __init__(self, name):
        self.name = name
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,  # 客户端使用2048位密钥
            backend=default_backend()
        )
        self.public_key = self.private_key.public_key()
        self.certificate = None

    def generate_csr(self, ca_public_key):
        # 生成最小化CSR
        csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, self.name),
        ])).sign(self.private_key, hashes.SHA256(), default_backend())

        # 使用压缩的DER格式
        csr_bytes = csr.public_bytes(serialization.Encoding.DER)

        # 拆分加密（当数据超过最大长度时）
        max_length = (ca_public_key.key_size // 8) - 66  # OAEP SHA-256的容量计算
        if len(csr_bytes) > max_length:
            raise ValueError(f"CSR数据过长 ({len(csr_bytes)} bytes)，最大允许 {max_length} bytes")

        encrypted_csr = ca_public_key.encrypt(
            csr_bytes,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return encrypted_csr


# 初始化CA
root_ca = CertificateAuthority("Root CA")
sub_ca1 = CertificateAuthority("Sub CA 1", parent=root_ca)
sub_ca2 = CertificateAuthority("Sub CA 2", parent=root_ca)

# 签发子CA证书
sub_ca1.certificate = root_ca.issue_certificate("Sub CA 1", sub_ca1.public_key)
sub_ca2.certificate = root_ca.issue_certificate("Sub CA 2", sub_ca2.public_key)

# 创建客户端
clients = [Client("Client1"), Client("Client2"), Client("Client3")]

# 证书签发流程
for i, client in enumerate(clients):
    target_ca = sub_ca1 if i < 2 else sub_ca2

    try:
        encrypted_csr = client.generate_csr(target_ca.public_key)
    except ValueError as e:
        print(f"加密失败: {e}")
        continue

    # 解密处理
    csr_bytes = target_ca.private_key.decrypt(
        encrypted_csr,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    csr = x509.load_der_x509_csr(csr_bytes, default_backend())

    # 签发证书
    client.certificate = target_ca.issue_certificate(client.name, client.public_key)

# 验证示例
if clients[0].certificate:
    print("验证结果:", sub_ca1.validate_certificate(clients[0].certificate))
    sub_ca1.revoke_certificate(clients[0].certificate.serial_number)
    print("吊销后验证:", sub_ca1.validate_certificate(clients[0].certificate))