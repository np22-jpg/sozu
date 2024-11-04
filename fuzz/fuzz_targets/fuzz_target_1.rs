#![no_main]
use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use sozu_command_lib::{
    channel::Channel,
    proto::command::{
        request::RequestType, AddBackend, Cluster, LoadBalancingAlgorithms, LoadBalancingParams,
        PathRule, RequestHttpFrontend, RulePosition, SocketAddress, WorkerRequest,
    },
};
use std::collections::BTreeMap;

#[derive(Arbitrary, Debug)]
struct FuzzInput {
    cluster_id: String,
    backend_id: String,
    hostname: String,
    path: String,
    owner_tag: String,
    id_tag: String,
    custom_message: String,
    port: u16,
}

fuzz_target!(|input: FuzzInput| {
    // Create channels with smaller buffer sizes for fuzzing
    if let Ok((mut command_channel, _)) = Channel::generate(10, 100) {
        // Create cluster with fuzzed data
        let cluster = Cluster {
            cluster_id: input.cluster_id.clone(),
            sticky_session: false,
            https_redirect: false,
            load_balancing: LoadBalancingAlgorithms::RoundRobin as i32,
            answer_503: Some(input.custom_message),
            ..Default::default()
        };

        // Create frontend with fuzzed data
        let http_front = RequestHttpFrontend {
            cluster_id: Some(input.cluster_id.clone()),
            address: SocketAddress::new_v4(127, 0, 0, 1, input.port),
            hostname: input.hostname,
            path: PathRule::prefix(input.path),
            position: RulePosition::Pre.into(),
            tags: BTreeMap::from([
                ("owner".to_owned(), input.owner_tag),
                ("id".to_owned(), input.id_tag),
            ]),
            ..Default::default()
        };

        // Create backend with fuzzed data
        let http_backend = AddBackend {
            cluster_id: input.cluster_id,
            backend_id: input.backend_id,
            address: SocketAddress::new_v4(127, 0, 0, 1, input.port),
            load_balancing_parameters: Some(LoadBalancingParams::default()),
            ..Default::default()
        };

        // Test cluster addition
        let _ = command_channel.write_message(&WorkerRequest {
            id: String::from("fuzz-cluster"),
            content: RequestType::AddCluster(cluster).into(),
        });

        // Test frontend addition
        let _ = command_channel.write_message(&WorkerRequest {
            id: String::from("fuzz-frontend"),
            content: RequestType::AddHttpFrontend(http_front).into(),
        });

        // Test backend addition
        let _ = command_channel.write_message(&WorkerRequest {
            id: String::from("fuzz-backend"),
            content: RequestType::AddBackend(http_backend).into(),
        });

        // Try to read responses
        let _: () = command_channel.read_message().unwrap();
        let _: () = command_channel.read_message().unwrap();
        let _: () = command_channel.read_message().unwrap();
    }
});
