use fnv::FnvHashMap;
use futures::channel::mpsc;
use libp2p::core::connection::{ConnectionId, ListenerId};
use libp2p::core::{ConnectedPoint, PublicKey};
use libp2p::identify::IdentifyInfo;
use libp2p::swarm::dial_opts::{DialOpts, PeerCondition};
use libp2p::swarm::handler::DummyConnectionHandler;
use libp2p::swarm::{
    self, ConnectionHandler, IntoConnectionHandler, NetworkBehaviour, NetworkBehaviourAction,
    PollParameters,
};
use libp2p::{Multiaddr, PeerId};
use std::collections::VecDeque;
use std::task::{Context, Poll};
use std::time::Duration;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Event {
    NewListener(ListenerId),
    NewListenAddr(ListenerId, Multiaddr),
    ExpiredListenAddr(ListenerId, Multiaddr),
    ListenerClosed(ListenerId),
    NewExternalAddr(Multiaddr),
    ExpiredExternalAddr(Multiaddr),
    Discovered(PeerId),
    Unreachable(PeerId),
    Connected(PeerId),
    Disconnected(PeerId),
    Bootstrapped,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct PeerInfo {
    protocol_version: Option<String>,
    agent_version: Option<String>,
    protocols: Vec<String>,
    addresses: FnvHashMap<Multiaddr, AddressSource>,
    rtt: Option<Duration>,
}

impl PeerInfo {
    pub fn protocol_version(&self) -> Option<&str> {
        self.protocol_version.as_deref()
    }

    pub fn agent_version(&self) -> Option<&str> {
        self.agent_version.as_deref()
    }

    pub fn protocols(&self) -> impl Iterator<Item = &str> + '_ {
        self.protocols.iter().map(|s| &**s)
    }

    pub fn addresses(&self) -> impl Iterator<Item = (&Multiaddr, AddressSource)> + '_ {
        self.addresses.iter().map(|(addr, source)| (addr, *source))
    }

    pub fn rtt(&self) -> Option<Duration> {
        self.rtt
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AddressSource {
    Mdns,
    Kad,
    Peer,
    User,
}

type AddressBookAction = swarm::NetworkBehaviourAction<
    <<<AddressBook as NetworkBehaviour>::ConnectionHandler as IntoConnectionHandler>::Handler as ConnectionHandler>::InEvent,
    <AddressBook as NetworkBehaviour>::ConnectionHandler
>;

#[derive(Debug)]
pub struct AddressBook {
    prune_addresses: bool,
    local_node_name: String,
    local_peer_id: PeerId,
    local_public_key: PublicKey,
    peers: FnvHashMap<PeerId, PeerInfo>,
    connections: FnvHashMap<PeerId, Multiaddr>,
    event_stream: Vec<mpsc::UnboundedSender<Event>>,
    actions: VecDeque<AddressBookAction>,
}

impl AddressBook {
    pub fn new(
        local_peer_id: PeerId,
        local_node_name: String,
        local_public_key: PublicKey,
        prune_addresses: bool,
    ) -> Self {
        Self {
            prune_addresses,
            local_node_name,
            local_peer_id,
            local_public_key,
            peers: Default::default(),
            connections: Default::default(),
            event_stream: Default::default(),
            actions: Default::default(),
        }
    }

    pub fn local_public_key(&self) -> &PublicKey {
        &self.local_public_key
    }

    pub fn local_peer_id(&self) -> &PeerId {
        &self.local_peer_id
    }

    pub fn local_node_name(&self) -> &str {
        &self.local_node_name
    }

    pub fn add_address(&mut self, peer: &PeerId, address: Multiaddr, source: AddressSource) {
        if peer == self.local_peer_id() {
            return;
        }
        let discovered = !self.peers.contains_key(peer);
        let info = self.peers.entry(*peer).or_default();
        info.addresses.entry(address.clone()).or_insert_with(|| {
            trace!("adding address {} from {:?}", address, source);
            source
        });
        if discovered {
            self.notify(Event::Discovered(*peer));
        }
    }

    pub fn remove_address(&mut self, peer: &PeerId, address: &Multiaddr) {
        if let Some(info) = self.peers.get_mut(peer) {
            tracing::trace!("removing address {}", address);
            info.addresses.remove(address);
        }
    }

    pub fn peers(&self) -> impl Iterator<Item = &PeerId> + '_ {
        self.peers.keys()
    }

    pub fn connections(&self) -> impl Iterator<Item = (&PeerId, &Multiaddr)> + '_ {
        self.connections.iter().map(|(peer, addr)| (peer, addr))
    }

    pub fn is_connected(&self, peer: &PeerId) -> bool {
        self.connections.contains_key(peer) || peer == self.local_peer_id()
    }

    pub fn info(&self, peer_id: &PeerId) -> Option<&PeerInfo> {
        self.peers.get(peer_id)
    }

    pub fn dial(&mut self, peer: &PeerId) {
        if peer == self.local_peer_id() {
            error!("attempting to dial self");
            return;
        }
        trace!("dialing {}", peer);
        self.actions.push_back(NetworkBehaviourAction::Dial {
            opts: DialOpts::peer_id(*peer)
                .condition(PeerCondition::Disconnected)
                .build(),
            handler: Default::default(),
        });
    }

    pub fn set_info(&mut self, peer_id: &PeerId, identify: IdentifyInfo) {
        if let Some(info) = self.peers.get_mut(peer_id) {
            info.protocol_version = Some(identify.protocol_version);
            info.agent_version = Some(identify.agent_version);
            info.protocols = identify.protocols;
        }
    }

    pub fn set_rtt(&mut self, peer_id: &PeerId, rtt: Option<Duration>) {
        if let Some(info) = self.peers.get_mut(peer_id) {
            info.rtt = rtt;
        }
    }

    pub fn notify(&mut self, event: Event) {
        trace!("{:?}", event);
        self.event_stream
            .retain(|tx| tx.unbounded_send(event.clone()).is_ok());
    }
}

impl NetworkBehaviour for AddressBook {
    type ConnectionHandler = DummyConnectionHandler;
    type OutEvent = void::Void;

    fn new_handler(&mut self) -> Self::ConnectionHandler {
        Default::default()
    }

    fn addresses_of_peer(&mut self, peer_id: &PeerId) -> Vec<Multiaddr> {
        if let Some(info) = self.peers.get(peer_id) {
            info.addresses().map(|(addr, _)| addr.clone()).collect()
        } else {
            vec![]
        }
    }

    fn inject_event(&mut self, _peer_id: PeerId, _connection: ConnectionId, _event: void::Void) {}

    fn poll(
        &mut self,
        _cx: &mut Context,
        _params: &mut impl PollParameters,
    ) -> Poll<NetworkBehaviourAction<Self::OutEvent, Self::ConnectionHandler>> {
        if let Some(action) = self.actions.pop_front() {
            Poll::Ready(action)
        } else {
            Poll::Pending
        }
    }

    fn inject_connection_established(
        &mut self,
        peer_id: &PeerId,
        _connection_id: &ConnectionId,
        endpoint: &ConnectedPoint,
        _failed_addresses: Option<&Vec<Multiaddr>>,
        _other_established: usize,
    ) {
        let address = endpoint.get_remote_address().clone();
        self.add_address(peer_id, address.clone(), AddressSource::Peer);
        self.connections.insert(*peer_id, address);
        self.notify(Event::Connected(*peer_id));
    }

    fn inject_connection_closed(
        &mut self,
        peer_id: &PeerId,
        _: &ConnectionId,
        _: &ConnectedPoint,
        _: <Self::ConnectionHandler as IntoConnectionHandler>::Handler,
        _remaining_established: usize,
    ) {
        self.connections.remove(peer_id);
        self.notify(Event::Disconnected(*peer_id));
    }

    fn inject_address_change(
        &mut self,
        peer_id: &PeerId,
        _: &ConnectionId,
        _old: &ConnectedPoint,
        new: &ConnectedPoint,
    ) {
        let new = new.get_remote_address().clone();
        self.add_address(peer_id, new.clone(), AddressSource::Peer);
        self.connections.insert(*peer_id, new);
    }

    fn inject_dial_failure(
        &mut self,
        peer_id: Option<PeerId>,
        _handler: Self::ConnectionHandler,
        error: &swarm::DialError,
    ) {
        if let Some(peer_id) = peer_id.as_ref() {
            if self.prune_addresses {
                // If an address was added after the peer was dialed retry dialing the
                // peer.
                if let Some(peer) = self.peers.get(peer_id) {
                    if !peer.addresses.is_empty() {
                        trace!("redialing with new addresses");
                        self.dial(peer_id);
                        return;
                    }
                }
            }
            trace!("dial failure {}, {}", peer_id, error);
            if self.peers.contains_key(peer_id) {
                self.notify(Event::Unreachable(*peer_id));
                if self.prune_addresses {
                    self.peers.remove(peer_id);
                }
            }
        }
    }

    fn inject_new_listener(&mut self, id: ListenerId) {
        trace!("listener {:?}: created", id);
        self.notify(Event::NewListener(id));
    }

    fn inject_new_listen_addr(&mut self, id: ListenerId, addr: &Multiaddr) {
        trace!("listener {:?}: new listen addr {}", id, addr);
        self.notify(Event::NewListenAddr(id, addr.clone()));
    }

    fn inject_expired_listen_addr(&mut self, id: ListenerId, addr: &Multiaddr) {
        trace!("listener {:?}: expired listen addr {}", id, addr);
        self.notify(Event::ExpiredListenAddr(id, addr.clone()));
    }

    fn inject_listener_error(&mut self, id: ListenerId, err: &(dyn std::error::Error + 'static)) {
        trace!("listener {:?}: listener error {}", id, err);
    }

    fn inject_listener_closed(&mut self, id: ListenerId, reason: Result<(), &std::io::Error>) {
        trace!("listener {:?}: closed for reason {:?}", id, reason);
        self.notify(Event::ListenerClosed(id));
    }

    fn inject_new_external_addr(&mut self, addr: &Multiaddr) {
        trace!("new external addr {}", addr);
        self.notify(Event::NewExternalAddr(addr.clone()));
    }

    fn inject_expired_external_addr(&mut self, addr: &Multiaddr) {
        trace!("expired external addr {}", addr);
        self.notify(Event::ExpiredExternalAddr(addr.clone()));
    }
}
