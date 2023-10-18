use std::collections::BTreeMap;

use command::{
    filtered_metrics::Inner, AggregatedMetrics, Bucket, ClusterMetrics, FilteredHistogram,
    FilteredMetrics,
};
use prost::DecodeError;

/// Contains all types received by and sent from Sōzu
pub mod command;

/// Implementation of fmt::Display for the protobuf types, used in the CLI
pub mod display;

#[derive(thiserror::Error, Debug)]
pub enum DisplayError {
    #[error("Could not display content")]
    DisplayContent(String),
    #[error("Error while parsing response to JSON")]
    Json(serde_json::Error),
    #[error("got the wrong response content type: {0}")]
    WrongResponseType(String),
    #[error("Could not format the datetime to ISO 8601")]
    DateTime,
    #[error("unrecognized protobuf variant: {0}")]
    DecodeError(DecodeError),
}

// Simple helper to build ResponseContent from ContentType
impl From<command::response_content::ContentType> for command::ResponseContent {
    fn from(value: command::response_content::ContentType) -> Self {
        Self {
            content_type: Some(value),
        }
    }
}

// Simple helper to build Request from RequestType
impl From<command::request::RequestType> for command::Request {
    fn from(value: command::request::RequestType) -> Self {
        Self {
            request_type: Some(value),
        }
    }
}

impl AggregatedMetrics {
    /// Merge metrics that were received from several workers
    ///
    /// Each worker gather the same kind of metrics,
    /// for its own proxying logic, and for the same clusters with their backends.
    /// This means we have to reduce each metric from N instances to 1.
    pub fn merge_metrics(&mut self) {
        // avoid copying the worker metrics, by taking them
        let workers = std::mem::take(&mut self.workers);

        for (_worker_id, worker) in workers {
            for (metric_name, new_value) in worker.proxy {
                if !new_value.is_mergeable() {
                    continue;
                }
                self.proxying
                    .entry(metric_name)
                    .and_modify(|old_value| old_value.merge(&new_value))
                    .or_insert(new_value);
            }

            for (cluster_id, mut cluster_metrics) in worker.clusters {
                for (metric_name, new_value) in cluster_metrics.cluster {
                    if !new_value.is_mergeable() {
                        continue;
                    }
                    self.clusters
                        .entry(cluster_id.to_owned())
                        .and_modify(|cluster| {
                            cluster
                                .cluster
                                .entry(metric_name.clone())
                                .and_modify(|old_value| old_value.merge(&new_value))
                                .or_insert(new_value.clone());
                        })
                        .or_insert(ClusterMetrics {
                            cluster: BTreeMap::from([(metric_name, new_value)]),
                            backends: Vec::new(),
                        });
                }

                for backend in cluster_metrics.backends.drain(..) {
                    for (metric_name, new_value) in &backend.metrics {
                        if !new_value.is_mergeable() {
                            continue;
                        }
                        self.clusters
                            .entry(cluster_id.to_owned())
                            .and_modify(|cluster| {
                                let found_backend = cluster
                                    .backends
                                    .iter_mut()
                                    .find(|present| present.backend_id == backend.backend_id);

                                let Some(existing_backend) = found_backend else {
                                    cluster.backends.push(backend.clone());
                                    return;
                                };

                                let _ = existing_backend
                                    .metrics
                                    .entry(metric_name.clone())
                                    .and_modify(|old_value| old_value.merge(&new_value))
                                    .or_insert(new_value.to_owned());
                            })
                            .or_insert(ClusterMetrics {
                                cluster: BTreeMap::new(),
                                backends: vec![backend.clone()],
                            });
                    }
                }
            }
        }
    }
}

impl FilteredMetrics {
    pub fn merge(&mut self, right: &Self) {
        match (&self.inner, &right.inner) {
            (Some(Inner::Gauge(a)), Some(Inner::Gauge(b))) => {
                *self = Self {
                    inner: Some(Inner::Gauge(a + b)),
                };
            }
            (Some(Inner::Count(a)), Some(Inner::Count(b))) => {
                *self = Self {
                    inner: Some(Inner::Count(a + b)),
                };
            }
            (Some(Inner::Histogram(a)), Some(Inner::Histogram(b))) => {
                let longest_len = a.buckets.len().max(b.buckets.len());

                let buckets = (0..longest_len)
                    .map(|i| Bucket {
                        le: (1 << i) - 1, // the bucket less-or-equal limits are normalized: 0, 1, 3, 7, 15, ...
                        count: a
                            .buckets
                            .get(i)
                            .and_then(|buck| Some(buck.count))
                            .unwrap_or(0)
                            + b.buckets
                                .get(i)
                                .and_then(|buck| Some(buck.count))
                                .unwrap_or(0),
                    })
                    .collect();

                *self = Self {
                    inner: Some(Inner::Histogram(FilteredHistogram {
                        count: a.count + b.count,
                        sum: a.sum + b.sum,
                        buckets,
                    })),
                };
            }
            _ => {}
        }
    }

    fn is_mergeable(&self) -> bool {
        match &self.inner {
            Some(Inner::Gauge(_)) | Some(Inner::Count(_)) | Some(Inner::Histogram(_)) => true,
            // Inner::Time and Inner::Timeserie are never used in Sōzu
            Some(Inner::Time(_))
            | Some(Inner::Percentiles(_))
            | Some(Inner::TimeSerie(_))
            | None => false,
        }
    }
}
