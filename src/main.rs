use actix_web::{post, web, App, HttpRequest, HttpResponse, HttpServer, Responder};
use std::env;
use std::fs;
use std::process::{Child, Command};
use std::sync::{Arc, Mutex};

struct AppState {
    ts_process: Mutex<Option<Child>>,
}

#[post("/webhook")]
async fn webhook(
    req: HttpRequest,
    payload: web::Bytes,
    state: web::Data<Arc<AppState>>,
) -> impl Responder {
    println!("Received push event to main branch. Pulling changes...");

    // Get the directory path from the environment variable
    let dir_path = env::var("JANKK_DIR").expect("JANKK_DIR environment variable not set");

    // Errors otherwise about file perms or something
    Command::new("git")
        .arg("add")
        .arg(".")
        .current_dir(&dir_path);
    Command::new("git")
        .arg("stash")
        .current_dir(&dir_path);

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
