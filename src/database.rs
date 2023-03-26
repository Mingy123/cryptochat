use k256::ecdsa::{VerifyingKey, Signature, signature::Verifier};

/* NOTE: the signature is DER encoded
because i cant find another way to deserialise it */
pub fn verify_msg (pubkey: &str, signature: &str, message: &str) -> bool {
    let pk = match VerifyingKey::from_sec1_bytes(
        match &hex::decode(pubkey) {
            Ok(val) => val,
            _ => return false
        }
    ) {
        Ok(val) => val,
        _ => return false
    };
    let sig = match Signature::from_der(
        match &hex::decode(signature) {
            Ok(val) => val,
            _ => return false
        }
    ) {
        Ok(val) => val,
        _ => return false
    };
    pk.verify(message.as_bytes(), &sig).is_ok()
}

#[macro_export]
macro_rules! query_one {
    ($query:expr, $conn:expr) => {{
        $query.fetch_one($conn).await
            .and_then(|r| Ok(r.try_get(0)?)).ok()
    }};
}

#[macro_export]
macro_rules! query_gen {
    ($query:expr, $conn:expr) => {{
        $query.fetch_one($conn).await
    }};
}

// 0: user is in group | 1: user is not in group | -1: group does not exist
#[macro_export]
macro_rules! user_in_group {
    ($uuid:expr, $user:expr, $conn:expr) => {{
        let mut ans = -1;
        if let Ok(members) = sqlx::query("SELECT members FROM groups WHERE uuid = ?")
            .bind($uuid).fetch_one($conn).await
        {
            let list: Vec<_> = members.try_get(0).unwrap_or("")
                .split(',').collect();
            let mut inner = 1;
            for pk in &list {
                if pk.eq($user) {
                    inner = 0;
                    break;
                }
            }
            ans = inner;
        }
        ans
    }};
}

//SELECT * FROM messages ORDER BY timestamp DESC LIMIT 50;
//SELECT * FROM messages WHERE uuid = 'asd' AND timestamp < 12345 ORDER BY timestamp DESC LIMIT 50;