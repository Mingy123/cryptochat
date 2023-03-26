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

// 0: is owner | 1: not owner | -1: group does not exist
#[macro_export]
macro_rules! user_is_owner {
    ($uuid:expr, $pubkey:expr, $conn:expr) => {{
        let mut ans = -1;
        if let Ok(owner) = sqlx::query("SELECT owner FROM groups WHERE uuid = ?")
            .bind($uuid).fetch_one($conn).await
        {
            if owner.get::<String, _>(0).eq($pubkey) { ans = 0 }
            else { ans = 1 }
        }
        ans
    }};
}

// WARNING: this may panic
// make sure that the query is "SELECT * FROM messages ..."
#[macro_export]
macro_rules! message_from_row {
    ($row:expr) => {{
        ChatMessage {
            content: $row.get(1),
            sender: $row.get(2),
            signature: $row.get(3),
            timestamp: $row.get(4),
            hash: $row.get::<String, _>(5).parse().unwrap()
        }
    }};
}