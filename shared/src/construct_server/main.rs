use construct_server_shared::run;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    run().await
}
