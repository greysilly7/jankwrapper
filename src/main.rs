use actix_web::{post, web, App, HttpRequest, HttpResponse, HttpServer, Responder};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::env;
use std::fs;
use std::process::{Child, Command};
use std::sync::{Arc, Mutex};
use subtle::ConstantTimeEq;

#[derive(Deserialize, Serialize)]
struct GitHubPayload {
    #[serde(rename = "ref")]
    git_ref: String,
    before: String,
    after: String,
    repository: Repository,
    pusher: Pusher,
    sender: Sender,
    created: bool,
    deleted: bool,
    forced: bool,
    base_ref: Option<String>,
    compare: String,
    commits: Vec<Commit>,
    head_commit: Option<Commit>,
}

#[derive(Deserialize, Serialize)]
struct Commit {
    id: String,
    tree_id: String,
    distinct: bool,
    message: String,
    timestamp: String,
    url: String,
    author: Author,
    committer: Committer,
    added: Vec<String>,
    removed: Vec<String>,
    modified: Vec<String>,
}

#[derive(Deserialize, Serialize)]
struct Author {
    name: String,
    email: String,
    username: Option<String>,
}

#[derive(Deserialize, Serialize)]
struct Committer {
    name: String,
    email: String,
    username: Option<String>,
}

#[derive(Deserialize, Serialize)]
struct Pusher {
    name: String,
    email: String,
}

#[derive(Deserialize, Serialize)]
struct Repository {
    id: u64,
    node_id: String,
    name: String,
    full_name: String,
    private: bool,
    owner: Owner,
    html_url: String,
    description: Option<String>,
    fork: bool,
    url: String,
    forks_url: String,
    keys_url: String,
    collaborators_url: String,
    teams_url: String,
    hooks_url: String,
    issue_events_url: String,
    events_url: String,
    assignees_url: String,
    branches_url: String,
    tags_url: String,
    blobs_url: String,
    git_tags_url: String,
    git_refs_url: String,
    trees_url: String,
    statuses_url: String,
    languages_url: String,
    stargazers_url: String,
    contributors_url: String,
    subscribers_url: String,
    subscription_url: String,
    commits_url: String,
    git_commits_url: String,
    comments_url: String,
    issue_comment_url: String,
    contents_url: String,
    compare_url: String,
    merges_url: String,
    archive_url: String,
    downloads_url: String,
    issues_url: String,
    pulls_url: String,
    milestones_url: String,
    notifications_url: String,
    labels_url: String,
    releases_url: String,
    deployments_url: String,
    created_at: u64,
    updated_at: String,
    pushed_at: u64,
    git_url: String,
    ssh_url: String,
    clone_url: String,
    svn_url: String,
    homepage: Option<String>,
    size: u64,
    stargazers_count: u64,
    watchers_count: u64,
    language: Option<String>,
    has_issues: bool,
    has_projects: bool,
    has_downloads: bool,
    has_wiki: bool,
    has_pages: bool,
    has_discussions: bool,
    forks_count: u64,
    mirror_url: Option<String>,
    archived: bool,
    disabled: bool,
    open_issues_count: u64,
    license: Option<License>,
    allow_forking: bool,
    is_template: bool,
    web_commit_signoff_required: bool,
    topics: Vec<String>,
    visibility: String,
    forks: u64,
    open_issues: u64,
    watchers: u64,
    default_branch: String,
    stargazers: u64,
    master_branch: String,
}

#[derive(Deserialize, Serialize)]
struct Owner {
    login: String,
    id: u64,
    node_id: String,
    avatar_url: String,
    gravatar_id: String,
    url: String,
    html_url: String,
    followers_url: String,
    following_url: String,
    gists_url: String,
    starred_url: String,
    subscriptions_url: String,
    organizations_url: String,
    repos_url: String,
    events_url: String,
    received_events_url: String,
    r#type: String,
    site_admin: bool,
}

#[derive(Deserialize, Serialize)]
struct Sender {
    login: String,
    id: u64,
    node_id: String,
    avatar_url: String,
    gravatar_id: String,
    url: String,
    html_url: String,
    followers_url: String,
    following_url: String,
    gists_url: String,
    starred_url: String,
    subscriptions_url: String,
    organizations_url: String,
    repos_url: String,
    events_url: String,
    received_events_url: String,
    r#type: String,
    site_admin: bool,
}

#[derive(Deserialize, Serialize)]
struct License {
    key: String,
    name: String,
    spdx_id: String,
    url: Option<String>,
    node_id: String,
}

struct AppState {
    ts_process: Mutex<Option<Child>>,
}

#[post("/webhook")]
async fn webhook(
    req: HttpRequest,
    payload: web::Bytes,
    state: web::Data<Arc<AppState>>,
) -> impl Responder {
    /*
    // Get the GitHub webhook secret from the environment variable
    let secret =
        env::var("GH_WEBHOOK_SECRET").expect("GH_WEBHOOK_SECRET environment variable not set");

    // Get the X-Hub-Signature-256 header
    let signature = match req.headers().get("X-Hub-Signature-256") {
        Some(sig) => sig.to_str().unwrap_or(""),
        None => return HttpResponse::Unauthorized().body("Missing signature"),
    };

    // Create HMAC instance
    type HmacSha256 = Hmac<Sha256>;
    let mut mac =
        HmacSha256::new_from_slice(secret.as_bytes()).expect("HMAC can take key of any size");
    mac.update(&payload);

    // Verify the signature
    let expected_signature = format!("sha256={}", hex::encode(mac.finalize().into_bytes()));
    if !constant_time_eq(expected_signature.as_bytes(), signature.as_bytes()) {
        return HttpResponse::Unauthorized().body("Invalid signature");
    }

    // Deserialize the payload
    let payload: GitHubPayload = match serde_json::from_slice(&payload) {
        Ok(payload) => payload,
        Err(_) => return HttpResponse::BadRequest().body("Invalid payload"),
    };

    // Check if the push is to the main branch
    if payload.git_ref != "refs/heads/main" {
        return HttpResponse::Ok().body("Push is not to the main branch. Ignoring.");
    }
    */

    println!("Received push event to main branch. Pulling changes...");

    // Get the directory path from the environment variable
    let dir_path = env::var("JANKK_DIR").expect("JANKK_DIR environment variable not set");

    // Pull the latest changes from the repository
    let pull_output = Command::new("git")
        .arg("pull")
        .current_dir(&dir_path)
        .output()
        .expect("Failed to execute git pull");

    if !pull_output.status.success() {
        let err = String::from_utf8_lossy(&pull_output.stderr);
        eprintln!("Git pull failed: {}", err);
        return HttpResponse::InternalServerError().body("Git pull failed");
    }

    println!("Git pull successful. Rebuilding JankClient using Gulp...");

    // Run Gulp to rebuild the project
    let gulp_output = Command::new("bun")
        .arg("gulp")
        .arg("--bunswc")
        .current_dir(&dir_path)
        .output()
        .expect("Failed to execute Gulp build");

    if !gulp_output.status.success() {
        let err = String::from_utf8_lossy(&gulp_output.stderr);
        eprintln!("Gulp build failed: {}", err);
        return HttpResponse::InternalServerError().body("Gulp build failed");
    }

    println!("Gulp build successful. Restarting JankClient...");

    // Restart the JankClient
    let mut ts_process_lock = state.ts_process.lock().unwrap();

    // Kill the current process if it's running
    if let Some(ref mut child) = *ts_process_lock {
        let _ = child.kill();
        println!("Killed the previous TypeScript process.");
    }

    // Start the new TypeScript process with Bun
    let new_process = Command::new("bun")
        .arg(format!("{}/dist/index.js", dir_path)) // Use the path from the environment variable
        .spawn();

    match new_process {
        Ok(child) => {
            *ts_process_lock = Some(child);
            println!("JankClient restarted successfully.");
            HttpResponse::Ok().body("JankClient restarted successfully.")
        }
        Err(e) => {
            eprintln!("Failed to restart JankClient: {}", e);
            HttpResponse::InternalServerError().body("Failed to restart JankClient.")
        }
    }
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    a.ct_eq(b).unwrap_u8() == 1
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    // Initialize the shared state
    let state = Arc::new(AppState {
        ts_process: Mutex::new(None),
    });

    // Get the directory path from the environment variable
    let dir_path = env::var("JANKK_DIR").expect("JANKK_DIR environment variable not set");

    if !fs::metadata(&dir_path).is_ok() {
        eprintln!("Directory path does not exist: {}", dir_path);

        println!("Cloning the repository...");

        match git2::Repository::clone("https://github.com/MathMan05/JankClient", &dir_path) {
            Ok(_) => println!("Cloned to {}", dir_path),
            Err(e) => panic!("failed to clone: {}", e),
        };
    }

    // Run Gulp to build the project on startup
    println!("Installing deps...");
    let bun_output = Command::new("bun")
        .arg("install")
        .current_dir(&dir_path)
        .output()
        .expect("Failed to execute bun install");

    if !bun_output.status.success() {
        let err = String::from_utf8_lossy(&bun_output.stderr);
        eprintln!("bun install failed: {}", err);
        return Err(std::io::Error::new(
            std::io::ErrorKind::Other,
            "bun install failed",
        ));
    }

    // Run Gulp to build the project on startup
    println!("Building JankClient using Gulp...");
    let gulp_output = Command::new("bun")
        .arg("gulp")
        .arg("--bunswc")
        .current_dir(&dir_path)
        .output()
        .expect("Failed to execute Gulp build");

    if !gulp_output.status.success() {
        let err = String::from_utf8_lossy(&gulp_output.stderr);
        eprintln!("Gulp build failed: {}", err);
        return Err(std::io::Error::new(
            std::io::ErrorKind::Other,
            "Gulp build failed",
        ));
    }

    println!("Gulp build successful. Starting JankClient...");

    // Start the initial JankClient using Bun
    {
        let mut ts_process_lock = state.ts_process.lock().unwrap();
        let process = Command::new("bun")
            .arg(format!("{}/dist/index.js", dir_path)) // Use the path from the environment variable
            .spawn();

        match process {
            Ok(child) => {
                *ts_process_lock = Some(child);
                println!("JankClient started successfully.");
            }
            Err(e) => {
                eprintln!("Failed to start JankClient: {}", e);
                return Err(std::io::Error::new(std::io::ErrorKind::Other, e));
            }
        }
    }

    // Start the HTTP server to listen for GitHub webhooks
    println!("Starting server on 0.0.0.0:7878...");
    HttpServer::new(move || {
        App::new()
            .app_data(web::Data::new(state.clone()))
            .service(webhook)
    })
    .bind("127.0.0.1:7878")?
    .run()
    .await
}
