//! Prova de tempo de passaportes e ações de moderação (#84).
//!
//! Assinaturas digitais não provam *quando* algo foi assinado: quem assina escolhe a data. Para
//! saber se um passaporte ou um ban veio antes de outro evento, cada objeto pode carregar
//! **carimbos** emitidos por terceiros sobre o hash dele. Um carimbo prova "este conteúdo já
//! existia no instante T" (limite superior), e é isso que impede datar algo no passado.
//!
//! Dois tipos de carimbo, verificados pela mesma interface:
//! - [`TimestampAttestation::Rfc3161`]: token de uma autoridade RFC 3161 (ex.: FreeTSA). As
//!   autoridades aceitas (URL e chave pública) ficam na configuração do servidor
//!   ([`TimestampPolicy`], gravada na `ServerChain`).
//! - [`TimestampAttestation::Peer`]: um membro do servidor faz o papel de TSA: recebe só o hash,
//!   carimba com o próprio relógio e assina. Para valer, a testemunha não pode descender de quem
//!   está sendo carimbado (regra de linhagem, aplicada em `chain.rs`).
//!
//! O limite inferior não vem de carimbo (quem cria o conteúdo poderia embutir uma referência
//! antiga): vem da data declarada `created_at`, aceita só se o carimbo mais antigo estiver a no
//! máximo [`TimestampPolicy::max_delay_secs`] dela. Assim o intervalo real fica preso entre os dois.

use super::passport::ServerPassport;
use super::UtcSecs;
use crate::identity::{verify_signature_hex, UserIdentity};
use base64::Engine as _;
use der::{
    asn1::{Int, Null, OctetString},
    oid::ObjectIdentifier,
    Any, Decode, Encode,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256, Sha384, Sha512};
use thiserror::Error;

/// Atraso máximo padrão entre a data declarada e o primeiro carimbo
pub const DEFAULT_MAX_STAMP_DELAY_SECS: u64 = 600;

/// URL pública da FreeTSA (RFC 3161), sugerida ao criar um servidor
pub const FREETSA_URL: &str = "https://freetsa.org/tsr";
/// Chave pública (SubjectPublicKeyInfo DER, base64) do certificado `www.freetsa.org` (ECDSA P-384,
/// válido até 2040; SHA-256 do certificado 32:E8:41:A9:...:DF:B1:91:FC)
pub const FREETSA_SPKI_B64: &str = "MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEohXhobLWy4cYsdKOFALpjUsB1FJTntwwb7PH2LOfNMAA1ufaKhkgsdeW6etU0pl5MC5tSVuPF52yy4sz+mbY3L7IVdx/bs9m0ud7IA14YNcC2yIQLa2gvnxwsrR3rlWr";

const OID_SIGNED_DATA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.7.2");
const OID_TST_INFO: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.16.1.4");
const OID_MESSAGE_DIGEST: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.4");
const OID_SHA256: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.1");
const OID_SHA384: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.2");
const OID_SHA512: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.3");
const OID_ECDSA_SHA256: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.2");
const OID_ECDSA_SHA384: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.3");
const OID_ECDSA_SHA512: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.4");
const OID_P256: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.3.1.7");
const OID_P384: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.132.0.34");

/// Uma autoridade de carimbo de tempo aceita pelo servidor
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct TrustedTsa {
    pub name: String,
    pub url: String,
    /// Chave pública da TSA (SubjectPublicKeyInfo DER). Aceita ECDSA P-256 e P-384.
    #[serde(with = "crate::b64")]
    pub spki_der: Vec<u8>,
}

impl TrustedTsa {
    pub fn freetsa() -> Self {
        Self {
            name: "FreeTSA".into(),
            url: FREETSA_URL.into(),
            spki_der: base64::engine::general_purpose::STANDARD.decode(FREETSA_SPKI_B64).expect("chave embutida válida"),
        }
    }
}

/// Política de prova de tempo do servidor (parte da configuração na `ServerChain`)
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct TimestampPolicy {
    pub tsas: Vec<TrustedTsa>,
    /// Atraso máximo aceito entre `created_at` e o carimbo mais antigo
    pub max_delay_secs: u64,
}

impl Default for TimestampPolicy {
    /// Política sugerida ao criar um servidor: FreeTSA + testemunhas da rede
    fn default() -> Self {
        Self { tsas: vec![TrustedTsa::freetsa()], max_delay_secs: DEFAULT_MAX_STAMP_DELAY_SECS }
    }
}

/// Carimbo de tempo sobre o hash ([`imprint`]) de um passaporte ou ação
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub enum TimestampAttestation {
    /// Token RFC 3161 (`TimeStampToken`, CMS SignedData) de uma TSA da política
    Rfc3161 {
        tsa: String,
        #[serde(with = "crate::b64")]
        token_der: Vec<u8>,
    },
    /// Co-assinatura de um membro do servidor no papel de TSA
    Peer(Box<PeerTimestampToken>),
}

/// Campos assinados pela testemunha
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct PeerTimestampBody {
    pub server_id: String,
    /// SHA-256 do conteúdo carimbado (hex)
    pub message_imprint: String,
    /// Relógio DA TESTEMUNHA no momento do carimbo (nunca vem do pedido)
    pub gen_time: UtcSecs,
    /// Nonce do pedido, contra reaproveitamento
    pub nonce: String,
    pub serial: String,
    /// Pubkey da testemunha
    pub witness: String,
}

/// Carimbo emitido por um membro: equivalente a um token RFC 3161, com o passaporte da
/// testemunha no lugar do certificado da TSA
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct PeerTimestampToken {
    pub body: PeerTimestampBody,
    pub witness_passport: ServerPassport,
    #[serde(with = "crate::b64")]
    pub signature: Vec<u8>,
}

impl PeerTimestampToken {
    /// Carimba `message_imprint` com o relógio local (`now`)
    pub fn issue(witness: &UserIdentity, witness_passport: &ServerPassport, message_imprint: &[u8; 32], nonce: &str, now: UtcSecs) -> Self {
        let body = PeerTimestampBody {
            server_id: witness_passport.body.server_id.clone(),
            message_imprint: hex(message_imprint),
            gen_time: now,
            nonce: nonce.to_string(),
            serial: hex(&rand::random::<[u8; 8]>()),
            witness: witness.public_key_hex(),
        };
        let signature = witness.sign(&crate::wire::signing_bytes("peer-tsa", &body));
        Self { body, witness_passport: witness_passport.clone(), signature }
    }

    /// Verificação estrutural: assinatura da testemunha, hash e passaporte dela no servidor.
    /// Validade do passaporte (bans) e linhagem são conferidas por quem conhece a cadeia.
    pub fn verify_structure(&self, server_id: &str, message_imprint: &[u8; 32]) -> Result<UtcSecs, TimestampError> {
        if self.body.server_id != server_id || self.witness_passport.body.server_id != server_id {
            return Err(TimestampError::WrongServer);
        }
        if self.body.message_imprint != hex(message_imprint) {
            return Err(TimestampError::ImprintMismatch);
        }
        if self.witness_passport.body.holder != self.body.witness {
            return Err(TimestampError::BadSignature);
        }
        if !verify_signature_hex(&self.body.witness, &crate::wire::signing_bytes("peer-tsa", &self.body), &self.signature) {
            return Err(TimestampError::BadSignature);
        }
        Ok(self.body.gen_time)
    }
}

#[derive(Error, Debug, PartialEq, Eq)]
pub enum TimestampError {
    #[error("token RFC 3161 malformado: {0}")]
    Malformed(String),
    #[error("o carimbo não corresponde a este conteúdo")]
    ImprintMismatch,
    #[error("assinatura do carimbo inválida ou de autoridade não aceita pelo servidor")]
    BadSignature,
    #[error("algoritmo não suportado: {0}")]
    Unsupported(String),
    #[error("carimbo de outro servidor")]
    WrongServer,
    #[error("a autoridade recusou o pedido: {0}")]
    Refused(String),
    #[error("falha de rede ao pedir o carimbo: {0}")]
    Network(String),
}

fn malformed(e: impl std::fmt::Display) -> TimestampError {
    TimestampError::Malformed(e.to_string())
}

/// Hash carimbado de um objeto assinado: cobre os bytes assinados **e** a assinatura, para que o
/// carimbo fique preso àquela assinatura específica
pub fn imprint(domain: &str, signing_bytes: &[u8], signature: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"anarchord-stamp/");
    hasher.update(domain.as_bytes());
    hasher.update([0]);
    hasher.update(signing_bytes);
    hasher.update(signature);
    hasher.finalize().into()
}

pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

/// Verifica um token RFC 3161 contra `message_imprint` e as TSAs aceitas.
/// Devolve o instante atestado (`genTime`) e o nome da TSA que assinou.
pub fn verify_rfc3161(token_der: &[u8], message_imprint: &[u8; 32], tsas: &[TrustedTsa]) -> Result<(UtcSecs, String), TimestampError> {
    let content_info = cms::content_info::ContentInfo::from_der(token_der).map_err(malformed)?;
    if content_info.content_type != OID_SIGNED_DATA {
        return Err(malformed("não é SignedData"));
    }
    let signed: cms::signed_data::SignedData = content_info.content.decode_as().map_err(malformed)?;
    if signed.encap_content_info.econtent_type != OID_TST_INFO {
        return Err(malformed("conteúdo não é TSTInfo"));
    }
    let econtent = signed.encap_content_info.econtent.as_ref().ok_or_else(|| malformed("TSTInfo ausente"))?;
    let tst_bytes = econtent.decode_as::<OctetString>().map_err(malformed)?.as_bytes().to_vec();
    let tst = x509_tsp::TstInfo::from_der(&tst_bytes).map_err(malformed)?;

    if tst.message_imprint.hash_algorithm.oid != OID_SHA256 || tst.message_imprint.hashed_message.as_bytes() != message_imprint {
        return Err(TimestampError::ImprintMismatch);
    }
    let gen_time = tst.gen_time.to_unix_duration().as_secs();

    for signer in signed.signer_infos.0.iter() {
        let Some(attrs) = &signer.signed_attrs else { continue };
        // messageDigest dos atributos assinados deve ser o hash do TSTInfo
        let expected = digest(&signer.digest_alg.oid, &tst_bytes)?;
        let digest_ok = attrs.iter().any(|attr| {
            attr.oid == OID_MESSAGE_DIGEST
                && attr.values.iter().any(|v| v.decode_as::<OctetString>().is_ok_and(|o| o.as_bytes() == expected.as_slice()))
        });
        if !digest_ok {
            continue;
        }
        // A assinatura cobre os atributos codificados como SET OF (tag universal, não o [0] implícito)
        let signed_bytes = attrs.to_der().map_err(malformed)?;
        let hash_oid = match signer.signature_algorithm.oid {
            OID_ECDSA_SHA256 => OID_SHA256,
            OID_ECDSA_SHA384 => OID_SHA384,
            OID_ECDSA_SHA512 => OID_SHA512,
            other => return Err(TimestampError::Unsupported(other.to_string())),
        };
        let prehash = digest(&hash_oid, &signed_bytes)?;
        let signature = signer.signature.as_bytes();
        for tsa in tsas {
            if verify_ecdsa(&tsa.spki_der, &prehash, signature) {
                return Ok((gen_time, tsa.name.clone()));
            }
        }
    }
    Err(TimestampError::BadSignature)
}

/// Horário declarado (`genTime`) de um token RFC 3161, sem verificar assinatura. Serve só para
/// ordenar; quem decide se o carimbo vale é [`verify_rfc3161`].
pub fn rfc3161_declared_time(token_der: &[u8]) -> Option<UtcSecs> {
    let content_info = cms::content_info::ContentInfo::from_der(token_der).ok()?;
    let signed: cms::signed_data::SignedData = content_info.content.decode_as().ok()?;
    let econtent = signed.encap_content_info.econtent?;
    let tst = x509_tsp::TstInfo::from_der(econtent.decode_as::<OctetString>().ok()?.as_bytes()).ok()?;
    Some(tst.gen_time.to_unix_duration().as_secs())
}

impl TimestampAttestation {
    /// Horário que o carimbo declara (sem verificar). Para ordenar antes de validar.
    pub fn declared_time(&self) -> Option<UtcSecs> {
        match self {
            TimestampAttestation::Rfc3161 { token_der, .. } => rfc3161_declared_time(token_der),
            TimestampAttestation::Peer(token) => Some(token.body.gen_time),
        }
    }
}

fn digest(oid: &ObjectIdentifier, data: &[u8]) -> Result<Vec<u8>, TimestampError> {
    Ok(match *oid {
        OID_SHA256 => Sha256::digest(data).to_vec(),
        OID_SHA384 => Sha384::digest(data).to_vec(),
        OID_SHA512 => Sha512::digest(data).to_vec(),
        other => return Err(TimestampError::Unsupported(other.to_string())),
    })
}

fn verify_ecdsa(spki_der: &[u8], prehash: &[u8], signature_der: &[u8]) -> bool {
    use p256::ecdsa::signature::hazmat::PrehashVerifier;
    let Ok(spki) = spki::SubjectPublicKeyInfoRef::from_der(spki_der) else { return false };
    let Some(curve) = spki.algorithm.parameters.and_then(|p| p.decode_as::<ObjectIdentifier>().ok()) else { return false };
    let point = spki.subject_public_key.raw_bytes();
    match curve {
        OID_P256 => {
            let (Ok(key), Ok(sig)) = (p256::ecdsa::VerifyingKey::from_sec1_bytes(point), p256::ecdsa::Signature::from_der(signature_der)) else {
                return false;
            };
            key.verify_prehash(prehash, &sig).is_ok()
        }
        OID_P384 => {
            let (Ok(key), Ok(sig)) = (p384::ecdsa::VerifyingKey::from_sec1_bytes(point), p384::ecdsa::Signature::from_der(signature_der)) else {
                return false;
            };
            key.verify_prehash(prehash, &sig).is_ok()
        }
        _ => false,
    }
}

/// Monta um `TimeStampReq` (DER) pedindo carimbo SHA-256 de `message_imprint`
pub fn rfc3161_request(message_imprint: &[u8; 32], nonce: &[u8; 8]) -> Vec<u8> {
    // INTEGER positivo em DER mínimo: sem zeros à esquerda, e 0x00 só se o bit alto estiver ligado
    let trimmed: Vec<u8> = nonce.iter().copied().skip_while(|b| *b == 0).collect();
    let mut nonce_bytes = if trimmed.first().is_none_or(|b| *b >= 0x80) { vec![0u8] } else { Vec::new() };
    nonce_bytes.extend_from_slice(&trimmed);
    let request = x509_tsp::TimeStampReq {
        version: x509_tsp::TspVersion::V1,
        message_imprint: x509_tsp::MessageImprint {
            hash_algorithm: spki::AlgorithmIdentifier { oid: OID_SHA256, parameters: Some(Any::from(Null)) },
            hashed_message: OctetString::new(message_imprint.to_vec()).expect("32 bytes"),
        },
        req_policy: None,
        nonce: Int::new(&nonce_bytes).ok(),
        cert_req: true,
        extensions: None,
    };
    request.to_der().expect("pedido codificável")
}

/// Extrai o token de uma `TimeStampResp`
pub fn rfc3161_parse_response(response_der: &[u8]) -> Result<Vec<u8>, TimestampError> {
    let response = x509_tsp::TimeStampResp::from_der(response_der).map_err(malformed)?;
    use cmpv2::status::PkiStatus;
    if !matches!(response.status.status, PkiStatus::Accepted | PkiStatus::GrantedWithMods) {
        return Err(TimestampError::Refused(format!("{:?}", response.status.status)));
    }
    response.time_stamp_token.ok_or_else(|| malformed("resposta sem token"))?.to_der().map_err(malformed)
}

/// Pede um carimbo a uma TSA via HTTP (bloqueante: chamar fora do loop de eventos)
pub fn fetch_rfc3161(tsa: &TrustedTsa, message_imprint: &[u8; 32]) -> Result<TimestampAttestation, TimestampError> {
    let request = rfc3161_request(message_imprint, &rand::random());
    let response = ureq::post(&tsa.url)
        .set("Content-Type", "application/timestamp-query")
        .timeout(std::time::Duration::from_secs(15))
        .send_bytes(&request)
        .map_err(|e| TimestampError::Network(e.to_string()))?;
    let mut body = Vec::new();
    std::io::Read::read_to_end(&mut response.into_reader().take(1 << 20), &mut body).map_err(|e| TimestampError::Network(e.to_string()))?;
    let token_der = rfc3161_parse_response(&body)?;
    verify_rfc3161(&token_der, message_imprint, std::slice::from_ref(tsa))?;
    Ok(TimestampAttestation::Rfc3161 { tsa: tsa.name.clone(), token_der })
}

use std::io::Read as _;

/// Gera tokens RFC 3161 com uma chave P-256 local (testes, sem rede)
#[cfg(test)]
pub(crate) mod test_tsa {
    use super::*;
    use der::asn1::GeneralizedTime;
    use cms::signed_data::{EncapsulatedContentInfo, SignedData, SignerIdentifier, SignerInfo, SignerInfos};
    use der::asn1::SetOfVec;
    use p256::ecdsa::{signature::hazmat::PrehashSigner, SigningKey};
    use p256::pkcs8::EncodePublicKey;

    pub struct LocalTsa {
        key: SigningKey,
    }

    impl LocalTsa {
        pub fn new() -> Self {
            Self { key: SigningKey::random(&mut rand::thread_rng()) }
        }

        pub fn trusted(&self, name: &str) -> TrustedTsa {
            let spki = self.key.verifying_key().to_public_key_der().unwrap();
            TrustedTsa { name: name.into(), url: "http://localhost/tsr".into(), spki_der: spki.as_bytes().to_vec() }
        }

        pub fn stamp(&self, message_imprint: &[u8; 32], at: UtcSecs) -> TimestampAttestation {
            TimestampAttestation::Rfc3161 { tsa: "local".into(), token_der: self.token(message_imprint, at) }
        }

        pub fn token(&self, message_imprint: &[u8; 32], at: UtcSecs) -> Vec<u8> {
            let alg = |oid| spki::AlgorithmIdentifierOwned { oid, parameters: None };
            let tst = x509_tsp::TstInfo {
                version: x509_tsp::TspVersion::V1,
                policy: ObjectIdentifier::new_unwrap("1.2.3.4.1"),
                message_imprint: x509_tsp::MessageImprint {
                    hash_algorithm: spki::AlgorithmIdentifier { oid: OID_SHA256, parameters: None },
                    hashed_message: OctetString::new(message_imprint.to_vec()).unwrap(),
                },
                serial_number: Int::new(&[1]).unwrap(),
                gen_time: GeneralizedTime::from_unix_duration(std::time::Duration::from_secs(at)).unwrap(),
                accuracy: None,
                ordering: false,
                nonce: None,
                tsa: None,
                extensions: None,
            };
            let tst_der = tst.to_der().unwrap();
            let message_digest = OctetString::new(Sha256::digest(&tst_der).to_vec()).unwrap();
            let attr = x509_cert::attr::Attribute {
                oid: OID_MESSAGE_DIGEST,
                values: SetOfVec::try_from(vec![Any::encode_from(&message_digest).unwrap()]).unwrap(),
            };
            let attrs: x509_cert::attr::Attributes = SetOfVec::try_from(vec![attr]).unwrap();
            let prehash = Sha256::digest(attrs.to_der().unwrap());
            let signature: p256::ecdsa::Signature = self.key.sign_prehash(&prehash).unwrap();
            let signer = SignerInfo {
                version: cms::content_info::CmsVersion::V3,
                sid: SignerIdentifier::SubjectKeyIdentifier(x509_cert::ext::pkix::SubjectKeyIdentifier(
                    OctetString::new(vec![1, 2, 3]).unwrap(),
                )),
                digest_alg: alg(OID_SHA256),
                signed_attrs: Some(attrs),
                signature_algorithm: alg(OID_ECDSA_SHA256),
                signature: OctetString::new(signature.to_der().as_bytes().to_vec()).unwrap(),
                unsigned_attrs: None,
            };
            let signed = SignedData {
                version: cms::content_info::CmsVersion::V3,
                digest_algorithms: SetOfVec::try_from(vec![alg(OID_SHA256)]).unwrap(),
                encap_content_info: EncapsulatedContentInfo {
                    econtent_type: OID_TST_INFO,
                    econtent: Some(Any::encode_from(&OctetString::new(tst_der).unwrap()).unwrap()),
                },
                certificates: None,
                crls: None,
                signer_infos: SignerInfos(SetOfVec::try_from(vec![signer]).unwrap()),
            };
            cms::content_info::ContentInfo { content_type: OID_SIGNED_DATA, content: Any::encode_from(&signed).unwrap() }.to_der().unwrap()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::test_tsa::LocalTsa;
    use super::*;

    /// Token real emitido pela FreeTSA em 2026-11-08 13:53:44 UTC sobre SHA-256("\n")
    const FREETSA_TOKEN: &[u8] = include_bytes!("testdata/freetsa_token.der");
    const NEWLINE_SHA256: &str = "01ba4719c80b6fe911b091a7c05124b64eeece964e09c058ef8f9805daca546b";

    fn newline_digest() -> [u8; 32] {
        let mut out = [0u8; 32];
        for (i, byte) in out.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&NEWLINE_SHA256[i * 2..i * 2 + 2], 16).unwrap();
        }
        out
    }

    #[test]
    fn test_real_freetsa_token_verifies_offline() {
        let (at, tsa) = verify_rfc3161(FREETSA_TOKEN, &newline_digest(), &[TrustedTsa::freetsa()]).expect("token da FreeTSA");
        assert_eq!(tsa, "FreeTSA");
        assert_eq!(at, 1_794_146_024, "2026-11-08 13:53:44 UTC");
    }

    #[test]
    fn test_freetsa_token_rejected_for_other_content_or_authority() {
        let mut other = newline_digest();
        other[0] ^= 1;
        assert_eq!(verify_rfc3161(FREETSA_TOKEN, &other, &[TrustedTsa::freetsa()]), Err(TimestampError::ImprintMismatch));
        let unknown = LocalTsa::new().trusted("outra");
        assert_eq!(verify_rfc3161(FREETSA_TOKEN, &newline_digest(), &[unknown]), Err(TimestampError::BadSignature), "TSA fora da política");
    }

    #[test]
    fn test_local_tsa_token_and_tampering() {
        let tsa = LocalTsa::new();
        let digest = imprint("teste", b"conteudo", b"assinatura");
        let token = tsa.token(&digest, 1_800_000_000);
        assert_eq!(verify_rfc3161(&token, &digest, &[tsa.trusted("local")]).map(|r| r.0), Ok(1_800_000_000));

        // Qualquer byte alterado invalida (data, hash ou assinatura)
        let mut tampered = token.clone();
        let len = tampered.len();
        tampered[len - 5] ^= 0x40;
        assert!(verify_rfc3161(&tampered, &digest, &[tsa.trusted("local")]).is_err());
        let forged = LocalTsa::new().token(&digest, 1_700_000_000);
        assert_eq!(verify_rfc3161(&forged, &digest, &[tsa.trusted("local")]), Err(TimestampError::BadSignature));
    }

    #[test]
    fn test_request_and_response_roundtrip() {
        let digest = imprint("x", b"a", b"b");
        let request = rfc3161_request(&digest, &[7; 8]);
        let parsed = x509_tsp::TimeStampReq::from_der(&request).unwrap();
        assert_eq!(parsed.message_imprint.hashed_message.as_bytes(), digest);
        assert!(parsed.cert_req);
        assert!(rfc3161_parse_response(b"lixo").is_err());
    }

    /// Pede um carimbo de verdade à FreeTSA (rede): `cargo test -- --ignored freetsa_live`
    #[test]
    #[ignore]
    fn test_freetsa_live() {
        let digest = imprint("teste-vivo", &rand::random::<[u8; 16]>(), b"sig");
        let stamp = fetch_rfc3161(&TrustedTsa::freetsa(), &digest).expect("FreeTSA respondeu");
        let TimestampAttestation::Rfc3161 { token_der, .. } = stamp else { unreachable!() };
        let (at, _) = verify_rfc3161(&token_der, &digest, &[TrustedTsa::freetsa()]).unwrap();
        let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
        assert!(at.abs_diff(now) < 300, "genTime próximo do relógio local");
    }

    #[test]
    fn test_imprint_binds_signature() {
        assert_ne!(imprint("passport", b"corpo", b"sig1"), imprint("passport", b"corpo", b"sig2"));
        assert_ne!(imprint("passport", b"corpo", b"sig"), imprint("modaction", b"corpo", b"sig"));
    }
}
