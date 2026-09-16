#[path = "routing/mod.rs"]
mod routing;
use routing::{Arc, RoadRouter};
use routing::rufield::{AwarenessPolicy, RuFieldRouter};
use rufield_core::FieldEvent;
use rufield_provenance::{Signer, TrustPolicy, TrustVerifier, TrustedKeyRegistry};
use rufield_ruvector::routing::prepare_routing_event;
#[test]
fn signed_sdk_event_replans_and_restores_real_backend() {
    let mut event: FieldEvent = serde_json::from_str(include_str!("ruview.json")).unwrap();
    let signer=Signer::from_seed(&[42;32]);
    signer.sign_event(&mut event).unwrap();
    let mut registry=TrustedKeyRegistry::new();
    registry.enroll_sensor_key(&event.sensor.device_id,signer.public_hex()).unwrap();
    let mut verifier=TrustVerifier::new(TrustPolicy::production_with_window(100,0),registry);
    let a=|source,target,cost| Arc{source,target,cost};
    let road=RoadRouter::new(4,vec![a(0,1,10),a(1,3,10),a(0,2,30),a(2,3,30)],vec![]).unwrap();
    let mut router=RuFieldRouter::new(road,AwarenessPolicy{max_penalty:100,close_at_millionths:800_000,ttl_ns:100,max_lateness_ns:0}).unwrap();
    router.bind_zone("room-a".into(),1).unwrap();
    assert_eq!(router.route(0,3,false,1000,||false).unwrap().unwrap().cost,20);
    let prepared=prepare_routing_event(&event,&mut verifier,100).unwrap();
    let result=prepared.deliver(100,|bytes,verified,now|router.ingest_json(bytes,verified,now)).unwrap().unwrap();
    assert_eq!(result.changed_arcs,2);
    assert_eq!(router.route(0,3,false,1000,||false).unwrap().unwrap().cost,60);
    assert!(prepared.deliver(100,|bytes,verified,now|router.ingest_json(bytes,verified,now)).unwrap().unwrap().duplicate);
    assert_eq!(router.expire(200).unwrap(),2);
    assert_eq!(router.route(0,3,false,1000,||false).unwrap().unwrap().cost,20);
}
