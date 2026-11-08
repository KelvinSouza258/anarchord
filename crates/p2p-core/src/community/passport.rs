//! Passaportes criptográficos do servidor (`ServerPassport`).
//!
//! Substitui o conceito antigo de convites de texto e allow-list centralizada na blockchain por
//! credenciais criptográficas verificáveis em cadeia com raiz única na Chave do Servidor (`server_id`).
//!
//! Regras Criptográficas e Hierárquicas:
//! 1. Raiz Soberana Única: O `server_id` (chave pública Ed25519 do servidor) é o Nível 0 e a única Raiz de Confiança.
//!    O criador do servidor (dono) possui um passaporte raiz emitido pela chave do servidor com Nível 1, todas as permissões
//!    e sem expiração (`expires_at: None`).
//! 2. Passaportes Vitalícios (`expires_at: None`):
//!    - PERMITIDOS EXCLUSIVAMENTE quando emitidos diretamente pela Chave do Servidor (`issuer == server_id`).
//!    - Se um intermediário/moderador emitir um passaporte com `expires_at: None`, ele é considerado INVÁLIDO.
//! 3. Monotonicidade Temporal:
//!    - Para passaportes com validade, `child.expires_at <= issuer.expires_at`.
//! 4. Monotonicidade Estrita de Nível (Prevenção de Conluio e Loops):
//!    - `child.level > issuer.level`. Dois moderadores de mesmo nível NÃO podem assinar passaportes um para o outro.
//! 5. Escopo de Permissões (Sem escalação de privilégio):
//!    - `child.permissions` deve ser um subconjunto estrito ou igual a `issuer.permissions`.
//!    - O emissor deve possuir `PassportPermission::IssueMember` (para emitir nível 255 / membros)
//!      ou `PassportPermission::Delegate` (para emitir níveis moderadores < 255).
//! 6. Achatamento Oportunista de Cadeia (`flatten_chain`):
//!    - Quando um nó com autoridade superior (ou que detém a Chave do Servidor) recebe uma cadeia válida,
//!      pode emitir um passaporte direto encurtando a cadeia para 1 elo.

use crate::identity::{verify_signature_hex, UserIdentity};
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Segundos Unix (UTC)
pub type UtcSecs = u64;

/// Tolerância padrão para desvios de relógio (5 minutos)
pub const CLOCK_SKEW_SECS: u64 = 300;

/// Nível máximo para membro comum (sem autoridade de moderação)
pub const MEMBER_LEVEL: u8 = 255;

/// O que um passaporte do servidor permite ao portador fazer
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum PassportPermission {
    /// Permite conectar ao servidor e descriptografar canais (MLS / chat / voz)
    EnterServer,
    /// Permite emitir passaportes para novos membros comuns (Nível 255)
    IssueMember,
    /// Permite criar sub-moderadores delegando permissões (Nível < 255)
    Delegate,
    /// Banir membros de nível estritamente superior ao seu
    Ban,
    /// Desbanir membros
    Unban,
    /// Criar, alterar e remover canais
    ManageChannels,
    /// Alterar nome e configurações estruturais do servidor
    ManageConfig,
}

impl PassportPermission {
    /// Conjunto completo de permissões soberanas (concedido ao Dono Nível 1 pelo Root)
    pub fn all() -> Vec<Self> {
        vec![
            PassportPermission::EnterServer,
            PassportPermission::IssueMember,
            PassportPermission::Delegate,
            PassportPermission::Ban,
            PassportPermission::Unban,
            PassportPermission::ManageChannels,
            PassportPermission::ManageConfig,
        ]
    }

    /// Permissões de um moderador padrão (Nível 2)
    pub fn default_moderator() -> Vec<Self> {
        vec![
            PassportPermission::EnterServer,
            PassportPermission::IssueMember,
            PassportPermission::Ban,
            PassportPermission::Unban,
        ]
    }

    /// Permissões de um membro comum (Nível 255)
    pub fn member() -> Vec<Self> {
        vec![PassportPermission::EnterServer]
    }
}

/// Corpo de dados canônico de um passaporte do servidor
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct PassportBody {
    /// Identificador único deste passaporte (usado para revogação pontual na ServerChain)
    pub serial: String,
    /// ID da Raiz do Servidor (pubkey hex de 64 caracteres do servidor)
    pub server_id: String,
    /// Pubkey hex do titular (dono deste passaporte)
    pub holder: String,
    /// Pubkey hex de quem assinou este elo (pode ser a chave do servidor ou um moderador ancestral)
    pub issuer: String,
    /// Nível de autoridade:
    /// - 0: Raiz Absoluta (Chave do Servidor)
    /// - 1: Dono / Moderador Supremo
    /// - 2..254: Sub-moderadores
    /// - 255: Membro comum
    pub level: u8,
    /// Permissões outorgadas ao titular
    pub permissions: Vec<PassportPermission>,
    /// Momento UTC da emissão
    pub issued_at: UtcSecs,
    /// Prazo de expiração UTC. `None` = Vitalício (PERMITIDO EXCLUSIVAMENTE quando `issuer == server_id`)
    pub expires_at: Option<UtcSecs>,
}

/// Passaporte Criptográfico do Servidor com Cadeia de Assinaturas
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct ServerPassport {
    pub body: PassportBody,
    /// Elo anterior da cadeia quando emitido por moderador (None se assinado diretamente pela Chave do Servidor)
    pub issuer_passport: Option<Box<ServerPassport>>,
    /// Assinatura Ed25519 do `body.issuer` sobre os `signing_bytes` de `body`
    #[serde(with = "crate::b64")]
    pub signature: Vec<u8>,
}

#[derive(Error, Debug, PartialEq, Eq)]
pub enum PassportError {
    #[error("ID de servidor incompatível: esperado {expected}, encontrado {found}")]
    ServerMismatch { expected: String, found: String },
    #[error("O primeiro elo da cadeia não foi assinado pela Chave do Servidor ({server_id})")]
    RootNotServerKey { server_id: String },
    #[error("Assinatura Ed25519 inválida do emissor {issuer}")]
    BadSignature { issuer: String },
    #[error("Violação de hierarquia: o nível do filho ({child_level}) deve ser estritamente maior que o do pai ({parent_level})")]
    LevelMustDecrease { parent_level: u8, child_level: u8 },
    #[error("Inconsistência na cadeia: o emissor declarado ({issuer}) não coincide com o titular do passaporte pai ({parent_holder})")]
    IssuerMismatch { parent_holder: String, issuer: String },
    #[error("Passaporte expirado: válido até {expires_at}, validado em {at}")]
    Expired { expires_at: UtcSecs, at: UtcSecs },
    #[error("Passaporte datado no futuro: emitido em {issued_at}, validado em {at}")]
    FromTheFuture { issued_at: UtcSecs, at: UtcSecs },
    #[error("Passaporte vitalício (sem expiração) é restrito à Chave do Servidor; moderadores não podem emitir vitalícios")]
    LifetimeOnlyForRoot,
    #[error("Validade excede a do emissor: pai expira em {parent_exp:?}, mas filho foi emitido até {child_exp:?}")]
    ValidityExceedsIssuer { parent_exp: Option<UtcSecs>, child_exp: Option<UtcSecs> },
    #[error("Emissor não possui permissão para emitir passaportes (necessário IssueMember ou Delegate)")]
    MissingDelegationPermission,
    #[error("Escalação de privilégio: permissão {0:?} não é concedida pelo passaporte do emissor")]
    EscalatedPermission(PassportPermission),
    #[error("Titular ou emissor revogado ou banido na cadeia do servidor: {0}")]
    RevokedOrBanned(String),
}

impl ServerPassport {
    /// Emite um passaporte de Raiz (Nível 0 -> Nível 1 ou Membro direto), assinado diretamente
    /// pela Chave do Servidor (`server_key`).
    ///
    /// Somente a Chave do Servidor pode emitir passaportes vitalícios (`expires_at: None`).
    pub fn issue_root(
        server_key: &UserIdentity,
        holder_pubkey: &str,
        level: u8,
        permissions: Vec<PassportPermission>,
        issued_at: UtcSecs,
        expires_at: Option<UtcSecs>,
    ) -> Self {
        let server_id = server_key.public_key_hex();
        let body = PassportBody {
            serial: random_serial(),
            server_id: server_id.clone(),
            holder: holder_pubkey.to_string(),
            issuer: server_id,
            level: level.max(1),
            permissions,
            issued_at,
            expires_at,
        };
        let signature = server_key.sign(&crate::wire::signing_bytes("passport", &body));
        Self { body, issuer_passport: None, signature }
    }

    /// Emite um passaporte subordinado a partir de um passaporte de moderador/dono já existente (`self`),
    /// estendendo a cadeia de assinaturas.
    ///
    /// Aplica as regras estritas:
    /// - `child.level > parent.level` (monotonicidade de níveis);
    /// - Intermediários NUNCA podem emitir vitalícios (`expires_at` DEVE ser `Some(ts)`);
    /// - `child.expires_at <= parent.expires_at`;
    /// - Sem escalação de privilégio (`permissions` deve ser subconjunto das permissões de `self`);
    /// - Emissor deve possuir `IssueMember` (para `level == 255`) ou `Delegate` (para `level < 255`).
    pub fn issue_subordinate(
        &self,
        issuer_identity: &UserIdentity,
        holder_pubkey: &str,
        new_level: u8,
        permissions: Vec<PassportPermission>,
        issued_at: UtcSecs,
        requested_expires_at: UtcSecs,
    ) -> Result<Self, PassportError> {
        let issuer_pubkey = issuer_identity.public_key_hex();
        if self.body.holder != issuer_pubkey {
            return Err(PassportError::IssuerMismatch {
                parent_holder: self.body.holder.clone(),
                issuer: issuer_pubkey,
            });
        }
        if new_level <= self.body.level {
            return Err(PassportError::LevelMustDecrease {
                parent_level: self.body.level,
                child_level: new_level,
            });
        }
        // Checagem de permissão de emissão
        if new_level == MEMBER_LEVEL {
            if !self.body.permissions.contains(&PassportPermission::IssueMember) {
                return Err(PassportError::MissingDelegationPermission);
            }
        } else if !self.body.permissions.contains(&PassportPermission::Delegate) {
            return Err(PassportError::MissingDelegationPermission);
        }

        // Sem escalação de privilégio
        for p in &permissions {
            if !self.body.permissions.contains(p) {
                return Err(PassportError::EscalatedPermission(*p));
            }
        }

        // Regra temporal monotônica: child.expires_at <= parent.expires_at
        let effective_expires_at = match self.body.expires_at {
            Some(parent_exp) => requested_expires_at.min(parent_exp),
            None => requested_expires_at, // Parent é vitalício (Root), mas filho gerado por moderador DEVE ter expiração finita
        };

        let body = PassportBody {
            serial: random_serial(),
            server_id: self.body.server_id.clone(),
            holder: holder_pubkey.to_string(),
            issuer: issuer_pubkey,
            level: new_level,
            permissions,
            issued_at,
            expires_at: Some(effective_expires_at),
        };

        let signature = issuer_identity.sign(&crate::wire::signing_bytes("passport", &body));
        Ok(Self {
            body,
            issuer_passport: Some(Box::new(self.clone())),
            signature,
        })
    }

    /// Valida toda a cadeia criptográfica de assinaturas até a Raiz do Servidor (`server_id`),
    /// verificando integridade de assinaturas, monotonicidade de níveis, escopo de permissões
    /// e prazos de validade temporal em `at`.
    pub fn verify_at(&self, expected_server_id: &str, at: UtcSecs) -> Result<(), PassportError> {
        self.verify_chain_recursive(expected_server_id, at)?;
        Ok(())
    }

    fn verify_chain_recursive(&self, expected_server_id: &str, at: UtcSecs) -> Result<(), PassportError> {
        if self.body.server_id != expected_server_id {
            return Err(PassportError::ServerMismatch {
                expected: expected_server_id.to_string(),
                found: self.body.server_id.clone(),
            });
        }

        // Validação da assinatura Ed25519 deste nó
        let signing_bytes = crate::wire::signing_bytes("passport", &self.body);
        if !verify_signature_hex(&self.body.issuer, &signing_bytes, &self.signature) {
            return Err(PassportError::BadSignature { issuer: self.body.issuer.clone() });
        }

        // Validação de tempo para este elo
        if self.body.issued_at > at + CLOCK_SKEW_SECS {
            return Err(PassportError::FromTheFuture {
                issued_at: self.body.issued_at,
                at,
            });
        }
        if let Some(exp) = self.body.expires_at {
            if at >= exp {
                return Err(PassportError::Expired { expires_at: exp, at });
            }
        }

        match &self.issuer_passport {
            None => {
                // Nó raiz da cadeia: DEVE ser assinado diretamente pela Chave do Servidor (server_id)
                if self.body.issuer != expected_server_id {
                    return Err(PassportError::RootNotServerKey {
                        server_id: expected_server_id.to_string(),
                    });
                }
            }
            Some(parent) => {
                // Intermediários NUNCA podem ter emitido passaportes vitalícios
                if self.body.expires_at.is_none() {
                    return Err(PassportError::LifetimeOnlyForRoot);
                }

                // Monotonicidade temporal: filho não pode expirar após o pai
                if let (Some(child_exp), Some(parent_exp)) = (self.body.expires_at, parent.body.expires_at) {
                    if child_exp > parent_exp {
                        return Err(PassportError::ValidityExceedsIssuer {
                            parent_exp: Some(parent_exp),
                            child_exp: Some(child_exp),
                        });
                    }
                }

                // Monotonicidade estrita de nível (anti-loop e anti-conluio)
                if self.body.level <= parent.body.level {
                    return Err(PassportError::LevelMustDecrease {
                        parent_level: parent.body.level,
                        child_level: self.body.level,
                    });
                }

                // Continuidade de identidade: o emissor deste elo é o titular do elo pai
                if self.body.issuer != parent.body.holder {
                    return Err(PassportError::IssuerMismatch {
                        parent_holder: parent.body.holder.clone(),
                        issuer: self.body.issuer.clone(),
                    });
                }

                // Emissor precisa de permissão para delegar
                if self.body.level == MEMBER_LEVEL {
                    if !parent.body.permissions.contains(&PassportPermission::IssueMember) {
                        return Err(PassportError::MissingDelegationPermission);
                    }
                } else if !parent.body.permissions.contains(&PassportPermission::Delegate) {
                    return Err(PassportError::MissingDelegationPermission);
                }

                // Sem escalação de privilégio
                for p in &self.body.permissions {
                    if !parent.body.permissions.contains(p) {
                        return Err(PassportError::EscalatedPermission(*p));
                    }
                }

                // Valida o pai recursivamente
                parent.verify_chain_recursive(expected_server_id, at)?;
            }
        }

        Ok(())
    }

    /// Retorna a profundidade da cadeia de assinaturas (1 = direto da Chave do Servidor, 2 = via 1 moderador, etc.)
    pub fn chain_depth(&self) -> usize {
        1 + self.issuer_passport.as_ref().map_or(0, |p| p.chain_depth())
    }

    /// Retorna a lista de todas as pubkeys participantes desta cadeia (`[holder, issuer1, issuer2, ..., root]`)
    pub fn all_participants(&self) -> Vec<String> {
        let mut list = vec![self.body.holder.clone()];
        let mut curr = self;
        while let Some(parent) = &curr.issuer_passport {
            list.push(parent.body.holder.clone());
            curr = parent;
        }
        list.push(curr.body.issuer.clone());
        list.dedup();
        list
    }

    /// Retorna todos os números seriais presentes nesta cadeia (para checagem contra revogações)
    pub fn all_serials(&self) -> Vec<String> {
        let mut serials = vec![self.body.serial.clone()];
        let mut curr = self;
        while let Some(parent) = &curr.issuer_passport {
            serials.push(parent.body.serial.clone());
            curr = parent;
        }
        serials
    }

    /// Verifica se este passaporte concede a permissão indicada
    pub fn allows(&self, permission: PassportPermission) -> bool {
        self.body.permissions.contains(&permission)
    }

    /// Menor data de expiração efetiva em toda a cadeia (a cadeia inteira vence quando o elo mais curto vencer)
    pub fn effective_expires_at(&self) -> Option<UtcSecs> {
        let mut min_exp = self.body.expires_at;
        let mut curr = self;
        while let Some(parent) = &curr.issuer_passport {
            if let Some(p_exp) = parent.body.expires_at {
                min_exp = Some(min_exp.map_or(p_exp, |c| c.min(p_exp)));
            }
            curr = parent;
        }
        min_exp
    }

    /// **Achatamento Oportunista de Cadeia (Chain Flattening):**
    /// Se um nó que possui a Chave do Servidor (`server_key`) recebe um passaporte válido (mesmo com vários elos),
    /// ele pode emitir diretamente um novo passaporte de 1 único elo (`Server -> Holder`), preservando
    /// exatamente o nível, permissões e validade do passaporte existente.
    pub fn flatten_with_server_key(&self, server_key: &UserIdentity, at: UtcSecs) -> Result<Self, PassportError> {
        let server_id = server_key.public_key_hex();
        self.verify_at(&server_id, at)?;

        let body = PassportBody {
            serial: random_serial(),
            server_id: server_id.clone(),
            holder: self.body.holder.clone(),
            issuer: server_id,
            level: self.body.level,
            permissions: self.body.permissions.clone(),
            issued_at: at,
            expires_at: self.effective_expires_at(),
        };

        let signature = server_key.sign(&crate::wire::signing_bytes("passport", &body));
        Ok(Self { body, issuer_passport: None, signature })
    }

    /// **Achatamento Oportunista por Superior Intermediário:**
    /// Se um moderador superior (`superior_passport`) com nível menor que o emissor atual do titular
    /// encontra o passaporte de `self`, pode reemitir um passaporte encurtado subordinado ao seu.
    pub fn flatten_with_superior(
        &self,
        superior_identity: &UserIdentity,
        superior_passport: &ServerPassport,
        at: UtcSecs,
    ) -> Result<Self, PassportError> {
        self.verify_at(&superior_passport.body.server_id, at)?;
        superior_passport.verify_at(&superior_passport.body.server_id, at)?;

        if superior_passport.body.level >= self.body.level {
            return Err(PassportError::LevelMustDecrease {
                parent_level: superior_passport.body.level,
                child_level: self.body.level,
            });
        }

        let effective_exp = match (self.effective_expires_at(), superior_passport.effective_expires_at()) {
            (Some(c), Some(p)) => c.min(p),
            (Some(c), None) => c,
            (None, Some(p)) => p,
            (None, None) => return Err(PassportError::LifetimeOnlyForRoot),
        };

        superior_passport.issue_subordinate(
            superior_identity,
            &self.body.holder,
            self.body.level,
            self.body.permissions.clone(),
            at,
            effective_exp,
        )
    }
}

fn random_serial() -> String {
    rand::random::<[u8; 8]>().iter().map(|b| format!("{:02x}", b)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_root_issue_and_verify_lifetime() {
        let server = UserIdentity::generate();
        let alice = UserIdentity::generate();
        let server_id = server.public_key_hex();

        // Passaporte vitalício de dono (Nível 1, todas as permissões, expires_at: None)
        let passport = ServerPassport::issue_root(
            &server,
            &alice.public_key_hex(),
            1,
            PassportPermission::all(),
            1000,
            None,
        );

        assert_eq!(passport.chain_depth(), 1);
        assert!(passport.verify_at(&server_id, 1000).is_ok());
        assert!(passport.verify_at(&server_id, 2_000_000_000).is_ok(), "vitalício não expira");
        assert!(passport.allows(PassportPermission::EnterServer));
        assert!(passport.allows(PassportPermission::Ban));
        assert!(passport.allows(PassportPermission::Delegate));
    }

    #[test]
    fn test_delegation_chain_alice_bob_carol() {
        let server = UserIdentity::generate();
        let server_id = server.public_key_hex();

        let alice = UserIdentity::generate();
        let bob = UserIdentity::generate();
        let carol = UserIdentity::generate();

        // 1. Servidor emite passaporte vitalício para Alice (Dona, Nível 1)
        let alice_passport = ServerPassport::issue_root(
            &server,
            &alice.public_key_hex(),
            1,
            PassportPermission::all(),
            1000,
            None,
        );
        assert!(alice_passport.verify_at(&server_id, 1000).is_ok());

        // 2. Alice emite passaporte para Bob (Moderador, Nível 2) válido por 7 dias
        let bob_passport = alice_passport
            .issue_subordinate(
                &alice,
                &bob.public_key_hex(),
                2,
                PassportPermission::default_moderator(),
                1000,
                1000 + 7 * 86_400,
            )
            .expect("alice delega para bob");
        assert_eq!(bob_passport.chain_depth(), 2);
        assert!(bob_passport.verify_at(&server_id, 1000).is_ok());

        // 3. Bob emite passaporte de membro comum (Nível 255) para Carol válido por 3 dias
        let carol_passport = bob_passport
            .issue_subordinate(
                &bob,
                &carol.public_key_hex(),
                MEMBER_LEVEL,
                PassportPermission::member(),
                1000,
                1000 + 3 * 86_400,
            )
            .expect("bob delega para carol");
        assert_eq!(carol_passport.chain_depth(), 3);
        assert!(carol_passport.verify_at(&server_id, 1000).is_ok());
        assert!(carol_passport.verify_at(&server_id, 1000 + 3 * 86_400 - 1).is_ok());
        assert!(carol_passport.verify_at(&server_id, 1000 + 3 * 86_400).is_err(), "carol expirou");

        // Lista de participantes e seriais
        let participants = carol_passport.all_participants();
        assert!(participants.contains(&carol.public_key_hex()));
        assert!(participants.contains(&bob.public_key_hex()));
        assert!(participants.contains(&alice.public_key_hex()));
        assert!(participants.contains(&server_id));
    }

    #[test]
    fn test_monotonic_time_rule_child_cannot_outlive_parent() {
        let server = UserIdentity::generate();
        let alice = UserIdentity::generate();
        let bob = UserIdentity::generate();
        let server_id = server.public_key_hex();

        // Alice tem passaporte com validade até t=2000
        let alice_passport = ServerPassport::issue_root(
            &server,
            &alice.public_key_hex(),
            1,
            PassportPermission::all(),
            1000,
            Some(2000),
        );

        // Bob solicita validade até t=5000: o método limita automaticamente a min(5000, 2000) = 2000
        let bob_passport = alice_passport
            .issue_subordinate(
                &alice,
                &bob.public_key_hex(),
                2,
                PassportPermission::default_moderator(),
                1000,
                5000,
            )
            .expect("subordinate criado");
        assert_eq!(bob_passport.body.expires_at, Some(2000));

        // Se um atacante forjar o campo expires_at de Bob para 5000 e recalcular a assinatura de Alice:
        let mut forged_bob = bob_passport.clone();
        forged_bob.body.expires_at = Some(5000);
        forged_bob.signature = alice.sign(&crate::wire::signing_bytes("passport", &forged_bob.body));

        let verify_result = forged_bob.verify_at(&server_id, 1000);
        assert_eq!(
            verify_result,
            Err(PassportError::ValidityExceedsIssuer {
                parent_exp: Some(2000),
                child_exp: Some(5000)
            })
        );
    }

    #[test]
    fn test_strict_level_monotonicity_anti_collusion() {
        let server = UserIdentity::generate();
        let mod_a = UserIdentity::generate();
        let mod_b = UserIdentity::generate();

        // Moderador A Nível 1
        let a_passport = ServerPassport::issue_root(
            &server,
            &mod_a.public_key_hex(),
            1,
            PassportPermission::all(),
            1000,
            Some(2000),
        );

        // Moderador A tenta emitir passaporte de Nível 1 para Moderador B: DEVE FALHAR
        let result = a_passport.issue_subordinate(
            &mod_a,
            &mod_b.public_key_hex(),
            1, // Mesmo nível!
            PassportPermission::default_moderator(),
            1000,
            1500,
        );
        assert_eq!(
            result,
            Err(PassportError::LevelMustDecrease {
                parent_level: 1,
                child_level: 1
            })
        );

        // Se tentar criar nível 0 (superior): DEVE FALHAR
        let result_superior = a_passport.issue_subordinate(
            &mod_a,
            &mod_b.public_key_hex(),
            0,
            PassportPermission::all(),
            1000,
            1500,
        );
        assert_eq!(
            result_superior,
            Err(PassportError::LevelMustDecrease {
                parent_level: 1,
                child_level: 0
            })
        );
    }

    #[test]
    fn test_lifetime_only_allowed_for_server_key_root() {
        let server = UserIdentity::generate();
        let alice = UserIdentity::generate();
        let bob = UserIdentity::generate();
        let server_id = server.public_key_hex();

        let alice_passport = ServerPassport::issue_root(
            &server,
            &alice.public_key_hex(),
            1,
            PassportPermission::all(),
            1000,
            None,
        );

        // Moderador intermediário forja expires_at = None
        let mut bob_body = alice_passport
            .issue_subordinate(
                &alice,
                &bob.public_key_hex(),
                2,
                PassportPermission::default_moderator(),
                1000,
                2000,
            )
            .unwrap()
            .body;
        bob_body.expires_at = None; // Forja vitalício!
        let bob_signature = alice.sign(&crate::wire::signing_bytes("passport", &bob_body));

        let forged_bob_passport = ServerPassport {
            body: bob_body,
            issuer_passport: Some(Box::new(alice_passport)),
            signature: bob_signature,
        };

        assert_eq!(
            forged_bob_passport.verify_at(&server_id, 1000),
            Err(PassportError::LifetimeOnlyForRoot)
        );
    }

    #[test]
    fn test_opportunistic_chain_flattening() {
        let server = UserIdentity::generate();
        let server_id = server.public_key_hex();

        let alice = UserIdentity::generate();
        let bob = UserIdentity::generate();
        let carol = UserIdentity::generate();

        // Cadeia de 3 elos: Server -> Alice -> Bob -> Carol
        let alice_p = ServerPassport::issue_root(&server, &alice.public_key_hex(), 1, PassportPermission::all(), 1000, None);
        let bob_p = alice_p
            .issue_subordinate(&alice, &bob.public_key_hex(), 2, PassportPermission::default_moderator(), 1000, 2000)
            .unwrap();
        let carol_p = bob_p
            .issue_subordinate(&bob, &carol.public_key_hex(), MEMBER_LEVEL, PassportPermission::member(), 1000, 1500)
            .unwrap();

        assert_eq!(carol_p.chain_depth(), 3);
        assert!(carol_p.verify_at(&server_id, 1000).is_ok());

        // Achatamento oportunista: quando o nó com a Chave do Servidor fica online,
        // ele reemite um passaporte direto para Carol:
        let flattened = carol_p.flatten_with_server_key(&server, 1100).expect("flatten com sucesso");

        assert_eq!(flattened.chain_depth(), 1, "cadeia reduzida para 1 elo direto");
        assert_eq!(flattened.body.holder, carol.public_key_hex());
        assert_eq!(flattened.body.issuer, server_id);
        assert_eq!(flattened.body.level, MEMBER_LEVEL);
        assert_eq!(flattened.body.expires_at, Some(1500), "mantém o prazo original");
        assert!(flattened.verify_at(&server_id, 1100).is_ok());
    }
}
