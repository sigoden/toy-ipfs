use ipfs_bitswap::{Bitswap, BitswapEvent};
use libp2p::core::PublicKey;
use libp2p::identify::{Identify, IdentifyEvent};
use libp2p::kad::record::Key;
use libp2p::kad::record::store::MemoryStore;
use libp2p::kad::{Kademlia, KademliaEvent, Record, Quorum};
use libp2p::mdns::{Mdns, MdnsEvent};
use libp2p::ping::{Ping, PingEvent, PingFailure, PingSuccess};
use libp2p::swarm::NetworkBehaviourEventProcess;
use libp2p::{Multiaddr, PeerId};
use multibase::Base;

use crate::error::{Error, Result};
use crate::network::peers::{AddressBook, AddressSource, Event, PeerInfo};
use crate::subscription::{SubscriptionFuture, SubscriptionRegistry};

/// Represents the result of a Kademlia query.
#[derive(Debug, Clone, PartialEq)]
pub enum KadResult {
    /// The query has been exhausted.
    Complete,
    /// The query successfully returns `GetClosestPeers` or `GetProviders` results.
    Peers(Vec<PeerId>),
    /// The query successfully returns a `GetRecord` result.
    Records(Vec<Record>),
}

pub struct IpfsBehaviour {
    identify: Identify,
    ping: Ping,
    mdns: Mdns,
    kad: Kademlia<MemoryStore>,
    bitswap: Bitswap,
    peers: AddressBook,
    bootstrap_complete: bool,
    kad_subscriptions: SubscriptionRegistry<KadResult, String>,
}

impl NetworkBehaviourEventProcess<void::Void> for IpfsBehaviour {
    fn inject_event(&mut self, _event: void::Void) {}
}

impl NetworkBehaviourEventProcess<MdnsEvent> for IpfsBehaviour {
    fn inject_event(&mut self, event: MdnsEvent) {
        match event {
            MdnsEvent::Discovered(list) => {
                for (peer_id, addr) in list {
                    self.add_address(&peer_id, addr, AddressSource::Mdns);
                }
            }
            MdnsEvent::Expired(_) => {
                // Ignore expired addresses
            }
        }
    }
}

impl NetworkBehaviourEventProcess<KademliaEvent> for IpfsBehaviour {
    fn inject_event(&mut self, event: KademliaEvent) {
        use libp2p::kad::{
            AddProviderError, AddProviderOk, BootstrapError, BootstrapOk, GetClosestPeersError,
            GetClosestPeersOk, GetProvidersError, GetProvidersOk, GetRecordError, GetRecordOk,
            KademliaEvent::*, PutRecordError, PutRecordOk, QueryResult::*,
        };

        match event {
            InboundRequest { request } => {
                trace!("kad: inbound {:?} request handled", request);
            }
            OutboundQueryCompleted { result, id, .. } => {
                // make sure the query is exhausted
                if self.kad.query(&id).is_none() {
                    match result {
                        // these subscriptions return actual values
                        GetClosestPeers(_) | GetProviders(_) | GetRecord(_) => {}
                        // we want to return specific errors for the following
                        Bootstrap(Err(_)) | StartProviding(Err(_)) | PutRecord(Err(_)) => {}
                        // and the rest can just return a general KadResult::Complete
                        _ => {
                            self.kad_subscriptions
                                .finish_subscription(id.into(), Ok(KadResult::Complete));
                        }
                    }
                }

                match result {
                    Bootstrap(Ok(BootstrapOk {
                        peer,
                        num_remaining,
                    })) => {
                        debug!(
                            "kad: bootstrapped with {}, {} peers remain",
                            peer, num_remaining
                        );
                        if num_remaining == 0 {
                            self.bootstrap_complete = true;
                            self.peers.notify(Event::Bootstrapped);
                        }
                    }
                    Bootstrap(Err(BootstrapError::Timeout { .. })) => {
                        warn!("kad: timed out while trying to bootstrap");

                        if self.kad.query(&id).is_none() {
                            self.kad_subscriptions.finish_subscription(
                                id.into(),
                                Err("kad: timed out while trying to bootstrap".into()),
                            );
                        }
                    }
                    GetClosestPeers(Ok(GetClosestPeersOk { key: _, peers })) => {
                        if self.kad.query(&id).is_none() {
                            self.kad_subscriptions
                                .finish_subscription(id.into(), Ok(KadResult::Peers(peers)));
                        }
                    }
                    GetClosestPeers(Err(GetClosestPeersError::Timeout { key: _, peers: _ })) => {
                        // don't mention the key here, as this is just the id of our node
                        warn!("kad: timed out while trying to find all closest peers");

                        if self.kad.query(&id).is_none() {
                            self.kad_subscriptions.finish_subscription(
                                id.into(),
                                Err("timed out while trying to get providers for the given key"
                                    .into()),
                            );
                        }
                    }
                    GetProviders(Ok(GetProvidersOk {
                        key: _,
                        providers,
                        closest_peers: _,
                    })) => {
                        if self.kad.query(&id).is_none() {
                            let providers = providers.into_iter().collect::<Vec<_>>();

                            self.kad_subscriptions
                                .finish_subscription(id.into(), Ok(KadResult::Peers(providers)));
                        }
                    }
                    GetProviders(Err(GetProvidersError::Timeout { key, .. })) => {
                        let key = multibase::encode(Base::Base32Lower, key);
                        warn!("kad: timed out while trying to get providers for {}", key);

                        if self.kad.query(&id).is_none() {
                            self.kad_subscriptions.finish_subscription(
                                id.into(),
                                Err("timed out while trying to get providers for the given key"
                                    .into()),
                            );
                        }
                    }
                    StartProviding(Ok(AddProviderOk { key })) => {
                        let key = multibase::encode(Base::Base32Lower, key);
                        debug!("kad: providing {}", key);
                    }
                    StartProviding(Err(AddProviderError::Timeout { key })) => {
                        let key = multibase::encode(Base::Base32Lower, key);
                        warn!("kad: timed out while trying to provide {}", key);

                        if self.kad.query(&id).is_none() {
                            self.kad_subscriptions.finish_subscription(
                                id.into(),
                                Err("kad: timed out while trying to provide the record".into()),
                            );
                        }
                    }
                    RepublishProvider(Ok(AddProviderOk { key })) => {
                        let key = multibase::encode(Base::Base32Lower, key);
                        debug!("kad: republished provider {}", key);
                    }
                    RepublishProvider(Err(AddProviderError::Timeout { key })) => {
                        let key = multibase::encode(Base::Base32Lower, key);
                        warn!("kad: timed out while trying to republish provider {}", key);
                    }
                    GetRecord(Ok(GetRecordOk { records, .. })) => {
                        if self.kad.query(&id).is_none() {
                            let records = records.into_iter().map(|rec| rec.record).collect();
                            self.kad_subscriptions
                                .finish_subscription(id.into(), Ok(KadResult::Records(records)));
                        }
                    }
                    GetRecord(Err(GetRecordError::NotFound {
                        key,
                        closest_peers: _,
                    })) => {
                        let key = multibase::encode(Base::Base32Lower, key);
                        warn!("kad: couldn't find record {}", key);

                        if self.kad.query(&id).is_none() {
                            self.kad_subscriptions.finish_subscription(
                                id.into(),
                                Err("couldn't find a record for the given key".into()),
                            );
                        }
                    }
                    GetRecord(Err(GetRecordError::QuorumFailed {
                        key,
                        records: _,
                        quorum,
                    })) => {
                        let key = multibase::encode(Base::Base32Lower, key);
                        warn!(
                            "kad: quorum failed {} when trying to get key {}",
                            quorum, key
                        );

                        if self.kad.query(&id).is_none() {
                            self.kad_subscriptions.finish_subscription(
                                id.into(),
                                Err("quorum failed when trying to obtain a record for the given key"
                                    .into()),
                            );
                        }
                    }
                    GetRecord(Err(GetRecordError::Timeout {
                        key,
                        records: _,
                        quorum: _,
                    })) => {
                        let key = multibase::encode(Base::Base32Lower, key);
                        warn!("kad: timed out while trying to get key {}", key);

                        if self.kad.query(&id).is_none() {
                            self.kad_subscriptions.finish_subscription(
                                id.into(),
                                Err("timed out while trying to get a record for the given key"
                                    .into()),
                            );
                        }
                    }
                    PutRecord(Ok(PutRecordOk { key }))
                    | RepublishRecord(Ok(PutRecordOk { key })) => {
                        let key = multibase::encode(Base::Base32Lower, key);
                        debug!("kad: successfully put record {}", key);
                    }
                    PutRecord(Err(PutRecordError::QuorumFailed {
                        key,
                        success: _,
                        quorum,
                    }))
                    | RepublishRecord(Err(PutRecordError::QuorumFailed {
                        key,
                        success: _,
                        quorum,
                    })) => {
                        let key = multibase::encode(Base::Base32Lower, key);
                        warn!(
                            "kad: quorum failed ({}) when trying to put record {}",
                            quorum, key
                        );

                        if self.kad.query(&id).is_none() {
                            self.kad_subscriptions.finish_subscription(
                                id.into(),
                                Err("kad: quorum failed when trying to put the record".into()),
                            );
                        }
                    }
                    PutRecord(Err(PutRecordError::Timeout {
                        key,
                        success: _,
                        quorum: _,
                    })) => {
                        let key = multibase::encode(Base::Base32Lower, key);
                        warn!("kad: timed out while trying to put record {}", key);

                        if self.kad.query(&id).is_none() {
                            self.kad_subscriptions.finish_subscription(
                                id.into(),
                                Err("kad: timed out while trying to put the record".into()),
                            );
                        }
                    }
                    RepublishRecord(Err(PutRecordError::Timeout {
                        key,
                        success: _,
                        quorum: _,
                    })) => {
                        let key = multibase::encode(Base::Base32Lower, key);
                        warn!("kad: timed out while trying to republish record {}", key);
                    }
                }
            }
            RoutingUpdated {
                peer,
                is_new_peer: _,
                addresses,
                bucket_range: _,
                old_peer: _,
            } => {
                trace!("kad: routing updated; {}: {:?}", peer, addresses);
            }
            UnroutablePeer { peer } => {
                trace!("kad: peer {} is unroutable", peer);
            }
            RoutablePeer { peer, address } => {
                trace!("kad: peer {} ({}) is routable", peer, address);
            }
            PendingRoutablePeer { peer, address } => {
                trace!("kad: pending routable peer {} ({})", peer, address);
            }
        }
    }
}

impl NetworkBehaviourEventProcess<BitswapEvent> for IpfsBehaviour {
    fn inject_event(&mut self, event: BitswapEvent) {
        todo!()
    }
}

impl NetworkBehaviourEventProcess<PingEvent> for IpfsBehaviour {
    fn inject_event(&mut self, event: PingEvent) {
        use std::result::Result;
        match event {
            PingEvent {
                peer,
                result: Result::Ok(PingSuccess::Ping { rtt }),
            } => {
                trace!(
                    "ping: rtt to {} is {} ms",
                    peer,
                    rtt.as_millis()
                );
                self.peers.set_rtt(&peer, Some(rtt));
            }
            PingEvent {
                peer,
                result: Result::Ok(PingSuccess::Pong),
            } => {
                trace!("ping: pong from {}", peer);
            }
            PingEvent {
                peer,
                result: Result::Err(PingFailure::Timeout),
            } => {
                trace!("ping: timeout to {}", peer);
                self.peers.set_rtt(&peer, None);
            }
            PingEvent {
                peer,
                result: Result::Err(PingFailure::Unsupported),
            } => {
                trace!("ping: unsupport to {}", peer);
                self.peers.set_rtt(&peer, None);
            }
            PingEvent {
                peer,
                result: Result::Err(PingFailure::Other { error }),
            } => {
                error!("ping: failure with {}: {}", peer, error);
                self.peers.set_rtt(&peer, None);
            }
        }
    }
}
impl NetworkBehaviourEventProcess<IdentifyEvent> for IpfsBehaviour {
    fn inject_event(&mut self, event: IdentifyEvent) {
        // When a peer opens a connection we only have it's outgoing address. The identify
        // protocol sends the listening address which needs to be registered with kademlia.
        if let IdentifyEvent::Received { peer_id, info } = event {
            let local_peer_id = *self.peers.local_peer_id();
            // source doesn't matter as it won't be added to address book.
            self.add_address(
                &local_peer_id,
                info.observed_addr.clone(),
                AddressSource::Peer,
            );
            self.peers.set_info(&peer_id, info);
        }
    }
}

impl IpfsBehaviour {
    pub fn new() {
        todo!()
    }
    pub fn local_public_key(&self) -> &PublicKey {
        self.peers.local_public_key()
    }

    pub fn local_node_name(&self) -> &str {
        self.peers.local_node_name()
    }

    pub fn add_address(&mut self, peer_id: &PeerId, addr: Multiaddr, source: AddressSource) {
        self.kad.add_address(peer_id, addr.clone());
        self.peers.add_address(peer_id, addr, source);
    }

    pub fn remove_address(&mut self, peer_id: &PeerId, addr: &Multiaddr) {
        self.peers.remove_address(peer_id, addr);
        self.kad.remove_address(peer_id, addr);
    }

    pub fn dial(&mut self, peer_id: &PeerId) {
        self.peers.dial(peer_id);
    }

    pub fn peers(&self) -> impl Iterator<Item = &PeerId> + '_ {
        self.peers.peers()
    }

    pub fn info(&self, peer_id: &PeerId) -> Option<&PeerInfo> {
        self.peers.info(peer_id)
    }

    pub fn connections(&self) -> impl Iterator<Item = (&PeerId, &Multiaddr)> + '_ {
        self.peers.connections()
    }

    pub fn is_connected(&self, peer: &PeerId) -> bool {
        self.peers.is_connected(peer)
    }

    pub fn bootstrap(&mut self) -> Result<SubscriptionFuture<KadResult, String>> {
        match self.kad.bootstrap() {
            Ok(id) => Ok(self.kad_subscriptions.create_subscription(id.into(), None)),
            Err(e) => {
                error!("kad: can't bootstrap the node: {:?}", e);
                Err(Error::KadBootstrapError(e.to_string()))
            }
        }
    }

    pub fn is_bootstrapped(&self) -> bool {
        self.bootstrap_complete
    }

    pub fn get_closest_peers(&mut self, id: PeerId) -> SubscriptionFuture<KadResult, String> {
        self.kad_subscriptions
            .create_subscription(self.kad.get_closest_peers(id).into(), None)
    }

    pub fn get_providers(&mut self, key: Key) -> SubscriptionFuture<KadResult, String> {
        self.kad_subscriptions
            .create_subscription(self.kad.get_providers(key).into(), None)
    }
    pub fn start_providing(
        &mut self,
        key: Key,
    ) -> Result<SubscriptionFuture<KadResult, String>> {
        match self.kad.start_providing(key) {
            Ok(id) => Ok(self.kad_subscriptions.create_subscription(id.into(), None)),
            Err(e) => {
                error!("kad: can't provide a key: {:?}", e);
                Err(Error::KadStartProvidingError(e.to_string()))
            }
        }
    }
    pub fn get_record(&mut self, key: Key, quorum: Quorum) -> SubscriptionFuture<KadResult, String> {
        self.kad_subscriptions
            .create_subscription(self.kad.get_record(key, quorum).into(), None)
    }

    pub fn dht_put(
        &mut self,
        key: Key,
        value: Vec<u8>,
        quorum: Quorum,
    ) -> Result<SubscriptionFuture<KadResult, String>> {
        let record = Record {
            key,
            value,
            publisher: None,
            expires: None,
        };
        match self.kad.put_record(record, quorum) {
            Ok(id) => Ok(self.kad_subscriptions.create_subscription(id.into(), None)),
            Err(e) => {
                error!("kad: can't put a record: {:?}", e);
                Err(Error::KadPutRecordEror(e.to_string()))
            }
        }
    }
}
