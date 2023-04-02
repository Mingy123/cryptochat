use std::collections::HashMap;
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::path::Path;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use database::*;
use rand::{thread_rng, Rng};
use rocket::{State, Shutdown};
use rocket::form::Form;
use rocket::fs::NamedFile;
use rocket::http::Status;
use rocket::request::{FromRequest, Outcome};
use rocket::response::stream::{EventStream, Event};
use rocket::serde::json::Json;
use rocket_db_pools::sqlx::{self, SqlitePool, Row};
use rocket_db_pools::{Connection, Database};
use rocket::serde::{Deserialize, Serialize};
use rocket::tokio::sync::broadcast::{channel, Sender, error::RecvError};
use rocket::tokio::select;
use uuid::Uuid;


const ALPHANUMERIC: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ\
                    abcdefghijklmnopqrstuvwxyz0123456789";

#[macro_use] extern crate rocket;
#[macro_use] mod database;

#[derive(Database)]
#[database("sqlite")]
pub struct ChatDB(SqlitePool);

#[derive(Deserialize, Serialize)]
struct User {
    pubkey: String,
    username: String,
    nonce: String
}

#[derive(Serialize, Clone)]
struct ChatMessage {
    content: String,
    sender: String,
    signature: String,
    timestamp: i64,
    hash: u64
}

#[derive(Serialize)]
struct ChatGroup {
    uuid: String,
    name: String,
    members: Vec<String>,
    owner: String,
    messages: Vec<ChatMessage>
}

#[rocket::async_trait]
impl<'r> FromRequest<'r> for User {
    type Error = ();

    async fn from_request(request: &'r rocket::Request<'_>) -> Outcome<Self, Self::Error> {
        let mut db = request.guard::<Connection<ChatDB>>()
            .await.succeeded().unwrap();
        let pubkey = match request.headers().get_one("X-Pubkey") {
            Some(n) => n,
            None => return Outcome::Failure((Status::BadRequest, ()))
        };
        let sig = match request.headers().get_one("X-Signature") {
            Some(n) => n,
            None => return Outcome::Failure((Status::BadRequest, ()))
        };

        let details: Result<(String, String), _> = query_gen!(
            sqlx::query("SELECT nonce, username FROM users WHERE pubkey = ?")
            .bind(pubkey), &mut *db).and_then(|row|
                Ok((row.try_get(0)?, row.try_get(1)?)));
        if let Ok((nonce, username)) = details {
            if !verify_msg(pubkey, sig, &nonce) {
                return Outcome::Failure((Status::Forbidden, ()));
            }
            return Outcome::Success(User { pubkey: pubkey.to_string(), username, nonce })
        }
        Outcome::Failure((Status::Forbidden, ()))
    }
}



// the fucking eventstream thing
struct MessageChannels { map: Mutex<HashMap<String, Sender<ChatMessage>>> }
#[derive(FromForm)] struct SubscribeForm { uuid: String }
#[post("/subscribe", data = "<form>")]
async fn subscribe(form: Form<SubscribeForm>, user: User, mut db: Connection<ChatDB>,
        state: &State<MessageChannels>, mut end: Shutdown) -> Option<EventStream![]> {
    if user_in_group!(&form.uuid, &user.pubkey, &mut *db) != 0 { return None }

    let mut lock = state.map.lock().expect("lock issue");
    let channel = match lock.get(&form.uuid) {
        Some(val) => val,
        _ => {
            let channel = channel::<ChatMessage>(1024).0;
            lock.insert(form.uuid.clone(), channel);
            lock.get(&form.uuid).expect("what the fuck?!?!?")
        }
    };
    let mut rx = channel.subscribe();
    Some(EventStream! {
        loop {
            let msg = select! {
                msg = rx.recv() => match msg {
                    Ok(msg) => msg,
                    Err(RecvError::Closed) => break,
                    Err(RecvError::Lagged(_)) => continue,
                },
                _ = &mut end => break,
            };

            yield Event::json(&msg);
        }
    })
}


// MESSAGING
#[derive(FromForm)]
struct MessageRequest {
    uuid: String,
    content: String,
    signature: String
}

#[post("/send", data = "<form>")]
async fn send_message(form: Form<MessageRequest>, user: User,
        mut db: Connection<ChatDB>, state: &State<MessageChannels>) -> &'static str {
    if user_in_group!(&form.uuid, &user.pubkey, &mut *db) != 0 {
        return "unprivileged"
    } if !verify_msg(&user.pubkey, &form.signature, &form.content) {
        return "signature fail"
    }

    // unix epoch thingy (Y2K38) is for i32. i64 should be perfectly fine
    let timestamp: i64 = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis()
        .try_into().unwrap();
    let mut hasher = DefaultHasher::new();
    form.uuid.hash(&mut hasher);
    form.content.hash(&mut hasher);
    user.pubkey.hash(&mut hasher);
    timestamp.hash(&mut hasher);
    let hash = hasher.finish();
    
    // INSERT INTO messages VALUES(uuid, content, sender, signature, timestamp, hash)
    let _ = query_gen!(sqlx::query(
        "INSERT INTO messages VALUES(?, ?, ?, ?, ?, ?)"
    ).bind(&form.uuid).bind(&form.content).bind(&user.pubkey).bind(form.signature.to_string())
    .bind(&timestamp).bind(hash.to_string()), &mut *db);

    let mut lock = state.map.lock().expect("lock issue");
    let sender = match lock.get(&form.uuid) {
        Some(val) => val,
        _ => {
            let channel = channel::<ChatMessage>(1024).0;
            lock.insert(form.uuid.clone(), channel);
            lock.get(&form.uuid).expect("what the fuck?!?!?")
        }
    };

    // A send 'fails' if there are no active subscribers. That's okay.
    let _ = sender.send(ChatMessage {
        content: form.content.clone(),
        sender: user.pubkey,
        signature: form.signature.clone(),
        timestamp: timestamp.into(),
        hash: hash.into()
    });

    "success"
}


/* im using a form bcos i cant find a way to get parameters from a GET request
which also has to be validated by the User FromRequest thing
works without parameters tho */
#[derive(FromForm)]
struct MessagesQuery { timestamp: i64, uuid: String }
#[post("/messages", data = "<form>")]
async fn messages_before(form: Form<MessagesQuery>, user: User,
        mut db: Connection<ChatDB>) -> Option<Json<Vec<ChatMessage>>> {
    if user_in_group!(&form.uuid, &user.pubkey, &mut *db) != 0 { return None }
    let query = match sqlx::query(
            "SELECT * FROM messages WHERE uuid = ? AND timestamp < ? ORDER BY timestamp DESC LIMIT 50"
        ).bind(&form.uuid).bind(form.timestamp).fetch_all(&mut *db).await {
            Ok(val) => val,
            _ => return None
        };
    Some(Json(query.iter().map(|row| message_from_row!(row)).collect()))
}

#[get("/message-info?<hash>")]
async fn message_info(hash: String, mut db: Connection<ChatDB>) -> Option<Json<(String, ChatMessage)>> {
    let ans = match query_gen!(sqlx::query(
            "SELECT * FROM messages WHERE hash = ?"
        ).bind(&hash), &mut *db) {
            Ok(val) => val,
            _ => return None
        };
    Some(Json((ans.get(0), message_from_row!(ans))))
}


// GROUP OPERATIONS
#[derive(FromForm, Serialize)]
struct GroupForm {
    uuid: String,
    #[field(default = "")]
    name: String,
    #[field(default = "")]
    owner: String
}

// list groups user is in
#[get("/my-groups")]
async fn joined_groups(user: User, mut db: Connection<ChatDB>) -> Option<Json<Vec<GroupForm>>> {
    let pk = format!("%{}%", user.pubkey);
    let query = 
        sqlx::query("SELECT * FROM groups WHERE members like ?").bind(pk);
    let result = match query.fetch_all(&mut *db).await {
        Ok(val) => {
            val.iter().map(
                |row| GroupForm {
                    uuid: row.get(0),
                    name: row.get(1),
                    owner: row.get(2)
                }
            ).collect()
        },
        _ => return None
    };
    Some(Json(result))
}

// create a group. returns uuid
#[post("/create-group")]
async fn create_group(user: User, mut db: Connection<ChatDB>) -> String {
    let mut uuid = Uuid::new_v4().to_string();
    while query_gen!(sqlx::query("SELECT name FROM groups WHERE uuid = ?")
        .bind(uuid.to_string()), &mut *db).is_ok()
    { uuid = Uuid::new_v4().to_string(); }

    // now write it to the database
    let _ = query_gen!(sqlx::query("insert into groups values(?, ?, ?, ?)")
        .bind(&uuid).bind(&uuid).bind(&user.pubkey).bind(&user.pubkey), &mut *db);
    uuid
}

#[post("/join-group", data = "<form>")]
async fn join_group(form: Form<GroupForm>, user: User,
        mut db: Connection<ChatDB>) -> &'static str {
    let ans = user_in_group!(&form.uuid, &user.pubkey, &mut *db);
    if ans == 0 { return "joined" }
    if ans == -1 { return "no such group" }

    let _ = query_gen!(sqlx::query("UPDATE groups SET members = members || ',' || ? WHERE uuid = ?")
        .bind(&user.pubkey).bind(&form.uuid), &mut *db);
    "success"
}

#[post("/rename-group", data = "<form>")]
async fn rename_group(form: Form<GroupForm>, user: User,
        mut db: Connection<ChatDB>) -> &'static str {
    match user_is_owner!(&form.uuid, &user.pubkey, &mut *db) {
        1 => return "not owner",
        -1 => return "no such group",
        _ => {}
    };

    let _ = query_gen!(sqlx::query(
        "UPDATE groups SET name = ? WHERE uuid = ?"
    ).bind(&form.name).bind(&form.uuid), &mut *db);
    "success"
}

#[post("/change-group-owner", data = "<form>")]
async fn change_group_owner(form: Form<GroupForm>,
        user: User, mut db: Connection<ChatDB>) -> &'static str {
    match user_is_owner!(&form.uuid, &user.pubkey, &mut *db) {
        1 => return "not owner",
        -1 => return "no such group",
        _ => {}
    };

    // check owner exists
    let res: Option<String> = query_one!(sqlx::query(
        "SELECT pubkey FROM users WHERE pubkey = ?"
    ).bind(&form.owner), &mut *db);
    if res.is_none() { return "new owner does not exist" }

    let _ = query_gen!(sqlx::query(
        "UPDATE groups SET owner = ? WHERE uuid = ?"
    ).bind(&form.owner).bind(&form.uuid), &mut *db);
    "success"
}

// last few msgs + name + members??
#[get("/group-info?<uuid>")]
async fn group_info(uuid: String, mut db: Connection<ChatDB>) -> Option<Json<ChatGroup>> {
    let row = match query_gen!(sqlx::query(
        "SELECT * FROM groups WHERE uuid = ?").bind(&uuid), &mut *db) {
            Ok(val) => val,
            _ => return None
        };
    let members = row.get::<String, _>(2).split(',').map(
        |s| s.to_string()).collect();

    // 1:content, 2:sender, 3:signature, 4:timestamp, 5:hash
    let messages = match sqlx::query(
            "SELECT * FROM messages WHERE uuid = ? ORDER BY timestamp DESC LIMIT 50"
        ).bind(&uuid).fetch_all(&mut *db).await {
            Ok(res) => res.iter().map(|row| message_from_row!(row)).collect(),
            _ => Vec::new()
        };
    Some(Json(ChatGroup {
        uuid: row.get(0),
        name: row.get(1),
        owner: row.get(3),
        members, messages
    }))
}

// delete group
#[post("/delete-group", data = "<form>")]
async fn delete_group(form: Form<GroupForm>, user: User,
        mut db: Connection<ChatDB>) -> &'static str {
    let owner: String = match query_one!(sqlx::query(
        "SELECT owner FROM groups WHERE uuid = ?"
    ).bind(&form.uuid), &mut *db) {
        Some(val) => val,
        _ => return "no such group"
    };
    if owner.eq(&user.pubkey) {
        let _ = query_gen!(sqlx::query(
            "DELETE FROM groups where uuid = ?"
        ).bind(&form.uuid), &mut *db);
    }
    "success"
}

#[get("/user-info?<pubkey>")]
async fn user_info(pubkey: String, mut db: Connection<ChatDB>) -> Option<Json<User>> {
    let row = match query_gen!(sqlx::query(
            "SELECT username, nonce FROM users WHERE pubkey = ?"
        ).bind(&pubkey), &mut *db) {
            Ok(val) => val,
            _ => return None
        };
    Some(Json(User{
        pubkey,
        username: row.get(0),
        nonce: row.get(1)
    }))
}


// RESETTING YOUR NONCE
struct TempNonce { map: Mutex<HashMap<String, String>> }
#[derive(FromForm)]
struct ResetForm {
    pubkey: String,
    signature: String,
}

#[get("/reset-nonce?<pubkey>")]
fn reset_nonce(pubkey: String, state: &State<TempNonce>) -> String {
    let mut rng = thread_rng();
    let nonce: String = (0..64).map(|_| {
        let idx = rng.gen_range(0..ALPHANUMERIC.len());
        ALPHANUMERIC[idx] as char
    }).collect();
    let mut map = state.map.lock().expect("lock issue");
    map.insert(pubkey, nonce.clone());
    nonce
}

#[post("/reset-nonce", data = "<form>")]
async fn confirm_reset_nonce(form: Form<ResetForm>, state: &State<TempNonce>,
        mut db: Connection<ChatDB>) -> &'static str {
    let nonce = {
        let map = state.map.lock().expect("lock");
        map.get(&form.pubkey).unwrap_or(&String::new()).clone()
    }; if nonce == String::new() { return "fail" }

    if !verify_msg(&form.pubkey, &form.signature, &nonce) { return "incorrect" }
    let _ = query_gen!(sqlx::query("UPDATE users SET nonce = ? WHERE pubkey = ?")
        .bind(nonce).bind(&form.pubkey), &mut *db);
    "success"
}

#[get("/")]
async fn index() -> Option<NamedFile> {
    NamedFile::open(Path::new("index.html")).await.ok()
}

#[launch]
fn rocket() -> _ {
    rocket::build()
        .attach(ChatDB::init())
        .manage(TempNonce{map: Mutex::new(HashMap::new())})
        .manage(MessageChannels{map: Mutex::new(HashMap::new())})
        .mount("/", routes![index, joined_groups, create_group, group_info,
            user_info, join_group, rename_group, change_group_owner,
            messages_before, send_message, message_info, subscribe, delete_group,
            reset_nonce, confirm_reset_nonce])
}