pub mod behaviour;
pub mod peers;
pub mod transport;

use crate::error::{Error, Result};
use libp2p::identity::Keypair;
use libp2p::Swarm;
use libp2p::{Multiaddr, PeerId};
use tracing::Span;

/// Defines the configuration for an IPFS network.
pub struct IpfsNetworkConfig {
    /// Manage addresses in the address book automatically. This removes
    /// them when an address is unreachable and removes the peer when there
    /// is a dial failure.
    pub prune_addresses: bool,
    /// Node name.
    pub node_name: String,
    /// Node key.
    pub node_key: Keypair,
    /// The peers to connect to on startup.
    pub bootstrap: Vec<(Multiaddr, PeerId)>,
    /// Enables mdns for peer discovery and announcement when true.
    pub mdns: bool,
    /// Custom Kademlia protocol name, see [`IpfsOptions::kad_protocol`].
    pub kad_protocol: Option<String>,
}

/// Creates a new IPFS swarm.
pub async fn create_swarm(
    config: IpfsNetworkConfig,
    span: Span,
) -> Result<Swarm<behaviour::IpfsBehaviour>> {
    let node_public_key = config.node_key.public();
    let peer_id = node_public_key.to_peer_id();

    // Set up an encrypted TCP transport over the Mplex protocol.
    let transport =
        transport::build_transport(config.node_key.clone()).map_err(Error::TransportError)?;

    // Create a Kademlia behaviour
    let behaviour = behaviour::IpfsBehaviour::create(config).await?;

    // Create a Swarm
    let swarm = libp2p::swarm::SwarmBuilder::new(transport, behaviour, peer_id)
        .executor(Box::new(SpannedExecutor(span)))
        .build();

    Ok(swarm)
}

struct SpannedExecutor(Span);

impl libp2p::core::Executor for SpannedExecutor {
    fn exec(
        &self,
        future: std::pin::Pin<Box<dyn std::future::Future<Output = ()> + 'static + Send>>,
    ) {
        use tracing_futures::Instrument;
        tokio::task::spawn(future.instrument(self.0.clone()));
    }
}
