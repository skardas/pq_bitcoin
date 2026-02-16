//! PQ Migration Indexer — Scans Bitcoin transactions for PQMG OP_RETURN payloads.
//!
//! # Architecture
//!
//! ```text
//! ┌──────────────┐     ┌──────────────┐     ┌──────────────┐
//! │ Bitcoin Node  │────▶│  Scanner     │────▶│  In-Memory   │
//! │ (RPC/ZMQ)    │     │  (blocks)    │     │  Store       │
//! └──────────────┘     └──────────────┘     └──────┬───────┘
//!                                                   │
//!                                            ┌──────▼───────┐
//!                                            │  REST API    │
//!                                            │  (axum)      │
//!                                            └──────────────┘
//! ```
//!
//! # Endpoints
//!
//! - `GET /api/migrations` — List all indexed migrations
//! - `GET /api/migrations/:txid` — Get migration by transaction ID
//! - `GET /api/migrations/key/:pq_hash` — Lookup by PQ key hash
//! - `GET /api/stats` — Index statistics
//! - `POST /api/scan` — Submit a raw OP_RETURN script for indexing

use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::Json,
    routing::{get, post},
    Router,
};
use bitcoin_hashes::{sha256, Hash};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use tower_http::cors::CorsLayer;

// ============================================================
//  OP_RETURN Constants (mirrors lib/src/op_return.rs)
// ============================================================

const MAGIC: [u8; 4] = *b"PQMG";
const VERSION: u8 = 0x01;
const PAYLOAD_SIZE: usize = 71;

const FLAG_GROTH16: u8 = 0x01;
const FLAG_PLONK: u8 = 0x02;
const FLAG_DUAL_SIG: u8 = 0x04;

const LEVEL_ML_DSA_44: u8 = 0x02;
const LEVEL_ML_DSA_65: u8 = 0x03;
const LEVEL_ML_DSA_87: u8 = 0x05;

// ============================================================
//  Data Types
// ============================================================

/// A decoded migration record from an OP_RETURN transaction.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MigrationRecord {
    /// Transaction ID (hex-encoded, 64 chars).
    pub txid: String,
    /// Block height where the transaction was mined.
    pub block_height: u64,
    /// Block timestamp (Unix epoch seconds).
    pub timestamp: u64,
    /// SHA-256 hash of the PQ public key (hex-encoded).
    pub pq_pubkey_hash: String,
    /// SHA-256 hash of the STARK proof (hex-encoded).
    pub proof_hash: String,
    /// Proof type flag.
    pub proof_type: String,
    /// Whether dual-sig mode is enabled.
    pub dual_sig: bool,
    /// ML-DSA security level.
    pub ml_dsa_level: String,
    /// Raw OP_RETURN payload (hex-encoded).
    pub raw_payload: String,
}

/// Index statistics.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IndexStats {
    pub total_migrations: usize,
    pub unique_pq_keys: usize,
    pub latest_block_height: u64,
    pub proof_type_breakdown: ProofTypeBreakdown,
    pub level_breakdown: LevelBreakdown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofTypeBreakdown {
    pub groth16: usize,
    pub plonk: usize,
    pub stark: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LevelBreakdown {
    pub ml_dsa_44: usize,
    pub ml_dsa_65: usize,
    pub ml_dsa_87: usize,
    pub unknown: usize,
}

/// Request body for submitting a raw script for indexing.
#[derive(Debug, Deserialize)]
pub struct ScanRequest {
    /// Hex-encoded raw OP_RETURN script.
    pub script_hex: String,
    /// Transaction ID (hex-encoded).
    pub txid: String,
    /// Block height.
    pub block_height: u64,
    /// Block timestamp.
    pub timestamp: u64,
}

/// API error response.
#[derive(Debug, Serialize)]
pub struct ApiError {
    pub error: String,
}

// ============================================================
//  In-Memory Store
// ============================================================

#[derive(Debug, Default)]
pub struct MigrationStore {
    /// All indexed migrations.
    records: Vec<MigrationRecord>,
    /// Index: txid → position in records.
    by_txid: HashMap<String, usize>,
    /// Index: pq_pubkey_hash → list of positions.
    by_pq_hash: HashMap<String, Vec<usize>>,
    /// Highest block height seen.
    latest_block: u64,
}

impl MigrationStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(&mut self, record: MigrationRecord) -> bool {
        // Reject duplicates.
        if self.by_txid.contains_key(&record.txid) {
            return false;
        }

        let idx = self.records.len();
        if record.block_height > self.latest_block {
            self.latest_block = record.block_height;
        }

        self.by_txid.insert(record.txid.clone(), idx);
        self.by_pq_hash
            .entry(record.pq_pubkey_hash.clone())
            .or_default()
            .push(idx);
        self.records.push(record);
        true
    }

    pub fn get_by_txid(&self, txid: &str) -> Option<&MigrationRecord> {
        self.by_txid.get(txid).map(|&idx| &self.records[idx])
    }

    pub fn get_by_pq_hash(&self, pq_hash: &str) -> Vec<&MigrationRecord> {
        self.by_pq_hash
            .get(pq_hash)
            .map(|indices| indices.iter().map(|&idx| &self.records[idx]).collect())
            .unwrap_or_default()
    }

    pub fn all(&self) -> &[MigrationRecord] {
        &self.records
    }

    pub fn stats(&self) -> IndexStats {
        let mut groth16 = 0;
        let mut plonk = 0;
        let mut stark = 0;
        let mut ml44 = 0;
        let mut ml65 = 0;
        let mut ml87 = 0;
        let mut unknown = 0;

        for r in &self.records {
            match r.proof_type.as_str() {
                "groth16" => groth16 += 1,
                "plonk" => plonk += 1,
                _ => stark += 1,
            }
            match r.ml_dsa_level.as_str() {
                "ML-DSA-44" => ml44 += 1,
                "ML-DSA-65" => ml65 += 1,
                "ML-DSA-87" => ml87 += 1,
                _ => unknown += 1,
            }
        }

        IndexStats {
            total_migrations: self.records.len(),
            unique_pq_keys: self.by_pq_hash.len(),
            latest_block_height: self.latest_block,
            proof_type_breakdown: ProofTypeBreakdown {
                groth16,
                plonk,
                stark,
            },
            level_breakdown: LevelBreakdown {
                ml_dsa_44: ml44,
                ml_dsa_65: ml65,
                ml_dsa_87: ml87,
                unknown,
            },
        }
    }
}

// ============================================================
//  Payload Decoder
// ============================================================

/// Decode a raw OP_RETURN script into a MigrationRecord.
///
/// Searches the script for the `PQMG` magic bytes and decodes
/// the 71-byte payload if found.
pub fn decode_migration_script(
    script: &[u8],
    txid: &str,
    block_height: u64,
    timestamp: u64,
) -> Option<MigrationRecord> {
    // Find the PQMG magic in the script.
    let payload = find_pqmg_payload(script)?;

    // Decode payload fields.
    let pq_pubkey_hash = hex::encode(&payload[5..37]);
    let proof_hash = hex::encode(&payload[37..69]);
    let flags = payload[69];
    let level = payload[70];

    let proof_type = if flags & FLAG_GROTH16 != 0 {
        "groth16"
    } else if flags & FLAG_PLONK != 0 {
        "plonk"
    } else {
        "stark"
    }
    .to_string();

    let dual_sig = flags & FLAG_DUAL_SIG != 0;

    let ml_dsa_level = match level {
        LEVEL_ML_DSA_44 => "ML-DSA-44",
        LEVEL_ML_DSA_65 => "ML-DSA-65",
        LEVEL_ML_DSA_87 => "ML-DSA-87",
        _ => "unknown",
    }
    .to_string();

    Some(MigrationRecord {
        txid: txid.to_string(),
        block_height,
        timestamp,
        pq_pubkey_hash,
        proof_hash,
        proof_type,
        dual_sig,
        ml_dsa_level,
        raw_payload: hex::encode(payload),
    })
}

/// Find the PQMG payload within a script (handles both raw and OP_RETURN-prefixed).
fn find_pqmg_payload(script: &[u8]) -> Option<&[u8]> {
    // Search for MAGIC bytes anywhere in the script.
    for i in 0..script.len().saturating_sub(PAYLOAD_SIZE - 1) {
        if script[i..i + 4] == MAGIC && i + PAYLOAD_SIZE <= script.len() {
            // Verify version byte.
            if script[i + 4] == VERSION {
                return Some(&script[i..i + PAYLOAD_SIZE]);
            }
        }
    }
    None
}

// ============================================================
//  API Handlers
// ============================================================

type SharedStore = Arc<RwLock<MigrationStore>>;

/// GET /api/migrations — list all migrations.
async fn list_migrations(State(store): State<SharedStore>) -> Json<Vec<MigrationRecord>> {
    let store = store.read().unwrap();
    Json(store.all().to_vec())
}

/// GET /api/migrations/:txid — get migration by transaction ID.
async fn get_migration(
    State(store): State<SharedStore>,
    Path(txid): Path<String>,
) -> Result<Json<MigrationRecord>, (StatusCode, Json<ApiError>)> {
    let store = store.read().unwrap();
    store
        .get_by_txid(&txid)
        .cloned()
        .map(Json)
        .ok_or((
            StatusCode::NOT_FOUND,
            Json(ApiError {
                error: format!("Migration not found for txid: {txid}"),
            }),
        ))
}

/// GET /api/migrations/key/:pq_hash — lookup by PQ key hash.
async fn get_by_pq_hash(
    State(store): State<SharedStore>,
    Path(pq_hash): Path<String>,
) -> Json<Vec<MigrationRecord>> {
    let store = store.read().unwrap();
    Json(store.get_by_pq_hash(&pq_hash).into_iter().cloned().collect())
}

/// GET /api/stats — index statistics.
async fn get_stats(State(store): State<SharedStore>) -> Json<IndexStats> {
    let store = store.read().unwrap();
    Json(store.stats())
}

/// POST /api/scan — submit a raw script for indexing.
async fn scan_script(
    State(store): State<SharedStore>,
    Json(req): Json<ScanRequest>,
) -> Result<Json<MigrationRecord>, (StatusCode, Json<ApiError>)> {
    let script_bytes = hex::decode(&req.script_hex).map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            Json(ApiError {
                error: "Invalid hex in script_hex".to_string(),
            }),
        )
    })?;

    let record =
        decode_migration_script(&script_bytes, &req.txid, req.block_height, req.timestamp)
            .ok_or((
                StatusCode::BAD_REQUEST,
                Json(ApiError {
                    error: "No valid PQMG payload found in script".to_string(),
                }),
            ))?;

    let mut store = store.write().unwrap();
    if !store.insert(record.clone()) {
        return Err((
            StatusCode::CONFLICT,
            Json(ApiError {
                error: format!("Duplicate txid: {}", req.txid),
            }),
        ));
    }

    Ok(Json(record))
}

/// GET / — health check.
async fn health() -> &'static str {
    "PQ Migration Indexer v0.1.0 — OK"
}

// ============================================================
//  Server
// ============================================================

pub fn create_router(store: SharedStore) -> Router {
    Router::new()
        .route("/", get(health))
        .route("/api/migrations", get(list_migrations))
        .route("/api/migrations/{txid}", get(get_migration))
        .route("/api/migrations/key/{pq_hash}", get(get_by_pq_hash))
        .route("/api/stats", get(get_stats))
        .route("/api/scan", post(scan_script))
        .layer(CorsLayer::permissive())
        .with_state(store)
}

#[tokio::main]
async fn main() {
    let store = Arc::new(RwLock::new(MigrationStore::new()));

    // ── Seed with demo data ────────────────────────────────────
    {
        let mut s = store.write().unwrap();

        // Create a sample PQ key and proof.
        let sample_pq_key = vec![0xAA; 1952]; // ML-DSA-65
        let sample_proof = b"sample-stark-proof-data";

        let pq_hash = sha256::Hash::hash(&sample_pq_key);
        let proof_hash = sha256::Hash::hash(sample_proof);

        // Build a PQMG payload manually.
        let mut payload = [0u8; PAYLOAD_SIZE];
        payload[0..4].copy_from_slice(&MAGIC);
        payload[4] = VERSION;
        payload[5..37].copy_from_slice(pq_hash.as_byte_array());
        payload[37..69].copy_from_slice(proof_hash.as_byte_array());
        payload[69] = FLAG_GROTH16;
        payload[70] = LEVEL_ML_DSA_65;

        // Decode and insert.
        if let Some(record) = decode_migration_script(
            &payload,
            "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2",
            850_000,
            1739600000,
        ) {
            s.insert(record);
        }
    }

    let port = std::env::var("PORT").unwrap_or_else(|_| "3030".to_string());
    let addr = format!("0.0.0.0:{port}");

    println!("╔══════════════════════════════════════════════════════════╗");
    println!("║       PQ Migration Indexer — REST API Server            ║");
    println!("╚══════════════════════════════════════════════════════════╝");
    println!();
    println!("  Listening on: http://{addr}");
    println!();
    println!("  Endpoints:");
    println!("    GET  /                          Health check");
    println!("    GET  /api/migrations            List all migrations");
    println!("    GET  /api/migrations/:txid      Get by transaction ID");
    println!("    GET  /api/migrations/key/:hash  Lookup by PQ key hash");
    println!("    GET  /api/stats                 Index statistics");
    println!("    POST /api/scan                  Submit raw OP_RETURN script");
    println!();
    println!("  Seeded with 1 demo migration");
    println!();

    let listener = tokio::net::TcpListener::bind(&addr).await.unwrap();
    axum::serve(listener, create_router(store)).await.unwrap();
}

// ============================================================
//  Tests
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::Request;
    use tower::ServiceExt;

    fn make_test_payload(flags: u8, level: u8) -> Vec<u8> {
        let pq_key = vec![0xAA; 1952];
        let proof = b"test-proof";
        let pq_hash = sha256::Hash::hash(&pq_key);
        let proof_hash = sha256::Hash::hash(proof);

        let mut payload = vec![0u8; PAYLOAD_SIZE];
        payload[0..4].copy_from_slice(&MAGIC);
        payload[4] = VERSION;
        payload[5..37].copy_from_slice(pq_hash.as_byte_array());
        payload[37..69].copy_from_slice(proof_hash.as_byte_array());
        payload[69] = flags;
        payload[70] = level;
        payload
    }

    // ── Payload Decoding ───────────────────────────────────────

    #[test]
    fn test_decode_valid_payload() {
        let payload = make_test_payload(FLAG_GROTH16, LEVEL_ML_DSA_65);
        let record = decode_migration_script(&payload, "tx1", 100, 1000).unwrap();
        assert_eq!(record.proof_type, "groth16");
        assert_eq!(record.ml_dsa_level, "ML-DSA-65");
        assert!(!record.dual_sig);
    }

    #[test]
    fn test_decode_plonk_flag() {
        let payload = make_test_payload(FLAG_PLONK, LEVEL_ML_DSA_44);
        let record = decode_migration_script(&payload, "tx2", 200, 2000).unwrap();
        assert_eq!(record.proof_type, "plonk");
        assert_eq!(record.ml_dsa_level, "ML-DSA-44");
    }

    #[test]
    fn test_decode_dual_sig() {
        let payload = make_test_payload(FLAG_GROTH16 | FLAG_DUAL_SIG, LEVEL_ML_DSA_87);
        let record = decode_migration_script(&payload, "tx3", 300, 3000).unwrap();
        assert!(record.dual_sig);
        assert_eq!(record.ml_dsa_level, "ML-DSA-87");
    }

    #[test]
    fn test_decode_stark_flag() {
        let payload = make_test_payload(0x00, LEVEL_ML_DSA_65);
        let record = decode_migration_script(&payload, "tx4", 400, 4000).unwrap();
        assert_eq!(record.proof_type, "stark");
    }

    #[test]
    fn test_decode_unknown_level() {
        let payload = make_test_payload(0x00, 0xFF);
        let record = decode_migration_script(&payload, "tx5", 500, 5000).unwrap();
        assert_eq!(record.ml_dsa_level, "unknown");
    }

    #[test]
    fn test_decode_invalid_magic() {
        let mut payload = make_test_payload(0x00, LEVEL_ML_DSA_65);
        payload[0] = 0xFF; // corrupt magic
        assert!(decode_migration_script(&payload, "tx6", 600, 6000).is_none());
    }

    #[test]
    fn test_decode_wrong_version() {
        let mut payload = make_test_payload(0x00, LEVEL_ML_DSA_65);
        payload[4] = 0xFF; // wrong version
        assert!(decode_migration_script(&payload, "tx7", 700, 7000).is_none());
    }

    #[test]
    fn test_decode_too_short() {
        let short = vec![0x50, 0x51, 0x4d, 0x47]; // just PQMG, too short
        assert!(decode_migration_script(&short, "tx8", 800, 8000).is_none());
    }

    #[test]
    fn test_decode_with_op_return_prefix() {
        let mut script = vec![0x6a, 0x4c, 71]; // OP_RETURN OP_PUSHDATA1 71
        script.extend_from_slice(&make_test_payload(FLAG_GROTH16, LEVEL_ML_DSA_65));
        let record = decode_migration_script(&script, "tx9", 900, 9000).unwrap();
        assert_eq!(record.proof_type, "groth16");
    }

    // ── Store ──────────────────────────────────────────────────

    #[test]
    fn test_store_insert_and_get() {
        let mut store = MigrationStore::new();
        let payload = make_test_payload(FLAG_GROTH16, LEVEL_ML_DSA_65);
        let record = decode_migration_script(&payload, "txA", 100, 1000).unwrap();
        assert!(store.insert(record.clone()));
        assert!(store.get_by_txid("txA").is_some());
    }

    #[test]
    fn test_store_reject_duplicate() {
        let mut store = MigrationStore::new();
        let payload = make_test_payload(FLAG_GROTH16, LEVEL_ML_DSA_65);
        let record = decode_migration_script(&payload, "txB", 100, 1000).unwrap();
        assert!(store.insert(record.clone()));
        assert!(!store.insert(record)); // duplicate
    }

    #[test]
    fn test_store_get_by_pq_hash() {
        let mut store = MigrationStore::new();
        let payload = make_test_payload(FLAG_GROTH16, LEVEL_ML_DSA_65);
        let record = decode_migration_script(&payload, "txC", 100, 1000).unwrap();
        let pq_hash = record.pq_pubkey_hash.clone();
        store.insert(record);
        let results = store.get_by_pq_hash(&pq_hash);
        assert_eq!(results.len(), 1);
    }

    #[test]
    fn test_store_get_by_pq_hash_not_found() {
        let store = MigrationStore::new();
        let results = store.get_by_pq_hash("deadbeef");
        assert!(results.is_empty());
    }

    #[test]
    fn test_store_stats() {
        let mut store = MigrationStore::new();
        let p1 = make_test_payload(FLAG_GROTH16, LEVEL_ML_DSA_65);
        let r1 = decode_migration_script(&p1, "tx1", 100, 1000).unwrap();
        store.insert(r1);

        let stats = store.stats();
        assert_eq!(stats.total_migrations, 1);
        assert_eq!(stats.proof_type_breakdown.groth16, 1);
        assert_eq!(stats.level_breakdown.ml_dsa_65, 1);
    }

    #[test]
    fn test_store_latest_block() {
        let mut store = MigrationStore::new();
        let p1 = make_test_payload(FLAG_GROTH16, LEVEL_ML_DSA_65);
        let r1 = decode_migration_script(&p1, "tx1", 100, 1000).unwrap();
        store.insert(r1);

        let p2 = make_test_payload(FLAG_PLONK, LEVEL_ML_DSA_44);
        let r2 = decode_migration_script(&p2, "tx2", 500, 5000).unwrap();
        store.insert(r2);

        assert_eq!(store.latest_block, 500);
    }

    // ── REST API ───────────────────────────────────────────────

    #[tokio::test]
    async fn test_health_endpoint() {
        let store = Arc::new(RwLock::new(MigrationStore::new()));
        let app = create_router(store);

        let response = app
            .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_list_migrations_empty() {
        let store = Arc::new(RwLock::new(MigrationStore::new()));
        let app = create_router(store);

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/api/migrations")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_stats_endpoint() {
        let store = Arc::new(RwLock::new(MigrationStore::new()));
        let app = create_router(store);

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/api/stats")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_scan_endpoint() {
        let store = Arc::new(RwLock::new(MigrationStore::new()));
        let app = create_router(store);

        let payload = make_test_payload(FLAG_GROTH16, LEVEL_ML_DSA_65);
        let body = serde_json::json!({
            "script_hex": hex::encode(&payload),
            "txid": "abc123",
            "block_height": 850000,
            "timestamp": 1739600000
        });

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/scan")
                    .header("Content-Type", "application/json")
                    .body(Body::from(serde_json::to_string(&body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_get_migration_not_found() {
        let store = Arc::new(RwLock::new(MigrationStore::new()));
        let app = create_router(store);

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/api/migrations/nonexistent")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_scan_invalid_hex() {
        let store = Arc::new(RwLock::new(MigrationStore::new()));
        let app = create_router(store);

        let body = serde_json::json!({
            "script_hex": "not-valid-hex",
            "txid": "tx1",
            "block_height": 100,
            "timestamp": 1000
        });

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/scan")
                    .header("Content-Type", "application/json")
                    .body(Body::from(serde_json::to_string(&body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_scan_no_pqmg_payload() {
        let store = Arc::new(RwLock::new(MigrationStore::new()));
        let app = create_router(store);

        let body = serde_json::json!({
            "script_hex": "6a0400112233",
            "txid": "tx1",
            "block_height": 100,
            "timestamp": 1000
        });

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/scan")
                    .header("Content-Type", "application/json")
                    .body(Body::from(serde_json::to_string(&body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_scan_duplicate_rejected() {
        let store = Arc::new(RwLock::new(MigrationStore::new()));
        let app = create_router(store.clone());

        let payload = make_test_payload(FLAG_GROTH16, LEVEL_ML_DSA_65);
        let body = serde_json::json!({
            "script_hex": hex::encode(&payload),
            "txid": "dup-tx",
            "block_height": 100,
            "timestamp": 1000
        });

        // First insert should succeed.
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/scan")
                    .header("Content-Type", "application/json")
                    .body(Body::from(serde_json::to_string(&body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        // Second insert (same txid) should be CONFLICT.
        let app2 = create_router(store);
        let response2 = app2
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/scan")
                    .header("Content-Type", "application/json")
                    .body(Body::from(serde_json::to_string(&body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response2.status(), StatusCode::CONFLICT);
    }
}
